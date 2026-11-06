#include "ScanEngine.hpp"
#include "NetworkProber.hpp"
#include "MacVendor.hpp"

#include <arpa/inet.h>
#include <future>
#include <algorithm>
#include <map>
#include <set>

ScanEngine::ScanEngine(const std::string& cidr_or_subnet)
    : target_ports_{21, 22, 23, 53, 80, 443, 445, 554, 1883, 3389, 8080, 8291, 8443, 8728, 9100, 62078} {
    parseCidrRange(cidr_or_subnet);
}

void ScanEngine::parseCidrRange(const std::string& input) {
    std::string ip_part = input;
    int prefix = 24;

    auto slash_pos = input.find('/');
    if (slash_pos != std::string::npos) {
        ip_part = input.substr(0, slash_pos);
        prefix = std::stoi(input.substr(slash_pos + 1));
    } else {
        if (std::count(ip_part.begin(), ip_part.end(), '.') == 2) {
            ip_part += ".0";
        }
    }

    if (prefix < 20) prefix = 20;
    if (prefix > 32) prefix = 32;

    in_addr addr{};
    if (inet_pton(AF_INET, ip_part.c_str(), &addr) <= 0) {
        ip_part = "192.168.1.0";
        inet_pton(AF_INET, ip_part.c_str(), &addr);
        prefix = 24;
    }

    uint32_t ip_num = ntohl(addr.s_addr);
    uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
    uint32_t net_start = ip_num & mask;
    uint32_t net_end = net_start | (~mask);

    in_addr net_addr{};
    net_addr.s_addr = htonl(net_start);
    char net_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &net_addr, net_str, INET_ADDRSTRLEN);
    cidr_ = std::string(net_str) + "/" + std::to_string(prefix);

    target_ips_.clear();
    if (prefix == 32) {
        target_ips_.push_back(ip_part);
    } else if (prefix == 31) {
        for (uint32_t cur = net_start; cur <= net_end; ++cur) {
            in_addr c_addr{htonl(cur)};
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &c_addr, buf, INET_ADDRSTRLEN);
            target_ips_.push_back(buf);
        }
    } else {
        for (uint32_t cur = net_start + 1; cur < net_end; ++cur) {
            in_addr c_addr{htonl(cur)};
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &c_addr, buf, INET_ADDRSTRLEN);
            target_ips_.push_back(buf);
        }
    }
}

std::shared_ptr<HostStats> ScanEngine::profileSingleHost(const std::string& ip, bool in_arp, const std::string& raw_mac, int timeout_ms) {
    bool is_alive = in_arp;
    std::optional<double> best_rtt = NetworkProber::probeIcmp(ip, timeout_ms);
    if (best_rtt.has_value()) {
        is_alive = true;
    }

    std::vector<int> open_ports;
    for (int port : target_ports_) {
        ProbeResult res = NetworkProber::probeTcpPort(ip, port, timeout_ms);
        if (res.host_alive) {
            is_alive = true;
            if (!best_rtt.has_value() && res.rtt_ms.has_value()) {
                best_rtt = res.rtt_ms;
            }
            if (res.port_open) {
                open_ports.push_back(port);
            }
        }
    }

    if (!is_alive) return nullptr;

    auto host = std::make_shared<HostStats>(ip);
    if (best_rtt.has_value()) {
        host->addSample(best_rtt);
    }
    host->setOpenPorts(open_ports);

    if (!raw_mac.empty()) {
        std::string norm_mac = MacVendor::normalizeMac(raw_mac);
        host->setMacAddress(norm_mac);
        host->setVendor(MacVendor::lookupVendor(norm_mac));
    }

    std::string hname = NetworkProber::resolveHostname(ip);
    if (!hname.empty()) {
        host->setHostname(hname);
    }

    return host;
}

void ScanEngine::discoverHosts(int timeout_ms) {
    struct DiscoveryItem {
        uint32_t ip_num;
        std::shared_ptr<HostStats> host;
    };

    const size_t batch_size = 128;

    for (size_t start = 0; start < target_ips_.size(); start += batch_size) {
        size_t end = std::min(start + batch_size, target_ips_.size());
        std::vector<std::future<void>> arp_futures;
        for (size_t i = start; i < end; ++i) {
            arp_futures.push_back(std::async(std::launch::async, [ip = target_ips_[i]]() {
                NetworkProber::triggerArpResolution(ip);
            }));
        }
        for (auto& f : arp_futures) f.get();
    }

    auto arp_table = NetworkProber::getSystemArpTable();
    std::vector<DiscoveryItem> found;

    for (size_t start = 0; start < target_ips_.size(); start += batch_size) {
        size_t end = std::min(start + batch_size, target_ips_.size());
        std::vector<std::future<DiscoveryItem>> futures;

        for (size_t i = start; i < end; ++i) {
            std::string ip = target_ips_[i];
            bool in_arp = (arp_table.find(ip) != arp_table.end());
            std::string raw_mac = in_arp ? arp_table[ip] : "";

            futures.push_back(std::async(std::launch::async, [this, ip, in_arp, raw_mac, timeout_ms]() -> DiscoveryItem {
                auto host = profileSingleHost(ip, in_arp, raw_mac, timeout_ms);
                if (host != nullptr) {
                    in_addr a{};
                    inet_pton(AF_INET, ip.c_str(), &a);
                    return {ntohl(a.s_addr), host};
                }
                return {0, nullptr};
            }));
        }

        for (auto& f : futures) {
            auto item = f.get();
            if (item.host != nullptr) {
                found.push_back(item);
            }
        }
    }

    std::sort(found.begin(), found.end(), [](const DiscoveryItem& a, const DiscoveryItem& b) {
        return a.ip_num < b.ip_num;
    });

    std::scoped_lock lock(hosts_mtx_);
    active_hosts_.clear();
    for (const auto& item : found) {
        active_hosts_.push_back(item.host);
    }
}

size_t ScanEngine::refreshTopology(int timeout_ms) {
    std::set<std::string> known_ips;
    {
        std::scoped_lock lock(hosts_mtx_);
        for (const auto& h : active_hosts_) {
            known_ips.insert(h->getIp());
        }
    }

    const size_t batch_size = 128;
    for (size_t start = 0; start < target_ips_.size(); start += batch_size) {
        size_t end = std::min(start + batch_size, target_ips_.size());
        std::vector<std::future<void>> arp_futures;
        for (size_t i = start; i < end; ++i) {
            if (known_ips.find(target_ips_[i]) == known_ips.end()) {
                arp_futures.push_back(std::async(std::launch::async, [ip = target_ips_[i]]() {
                    NetworkProber::triggerArpResolution(ip);
                }));
            }
        }
        for (auto& f : arp_futures) f.get();
    }

    auto arp_table = NetworkProber::getSystemArpTable();
    std::vector<std::future<std::shared_ptr<HostStats>>> new_futures;

    for (const auto& [ip, raw_mac] : arp_table) {
        if (known_ips.find(ip) == known_ips.end()) {
            if (std::find(target_ips_.begin(), target_ips_.end(), ip) != target_ips_.end()) {
                new_futures.push_back(std::async(std::launch::async, [this, ip, raw_mac, timeout_ms]() {
                    return profileSingleHost(ip, true, raw_mac, timeout_ms);
                }));
            }
        }
    }

    std::vector<std::shared_ptr<HostStats>> new_hosts;
    for (auto& f : new_futures) {
        auto h = f.get();
        if (h != nullptr) {
            new_hosts.push_back(h);
        }
    }

    if (!new_hosts.empty()) {
        std::scoped_lock lock(hosts_mtx_);
        for (auto& nh : new_hosts) {
            active_hosts_.push_back(nh);
        }
        std::sort(active_hosts_.begin(), active_hosts_.end(), [](const auto& a, const auto& b) {
            in_addr addr_a{}, addr_b{};
            inet_pton(AF_INET, a->getIp().c_str(), &addr_a);
            inet_pton(AF_INET, b->getIp().c_str(), &addr_b);
            return ntohl(addr_a.s_addr) < ntohl(addr_b.s_addr);
        });
    }

    return new_hosts.size();
}

void ScanEngine::pingActiveHosts(int timeout_ms) {
    auto hosts = getActiveHosts();
    std::vector<std::future<void>> futures;
    futures.reserve(hosts.size());

    for (auto& host : hosts) {
        futures.push_back(std::async(std::launch::async, [host, timeout_ms]() {
            auto open_ports = host->getOpenPorts();
            int probe_port = open_ports.empty() ? 80 : open_ports.front();

            ProbeResult tcp_res = NetworkProber::probeTcpPort(host->getIp(), probe_port, timeout_ms);
            if (tcp_res.host_alive && tcp_res.rtt_ms.has_value()) {
                host->addSample(tcp_res.rtt_ms);
                return;
            }

            auto icmp_rtt = NetworkProber::probeIcmp(host->getIp(), timeout_ms);
            if (icmp_rtt.has_value()) {
                host->addSample(icmp_rtt);
            } else {
                host->addSample(std::nullopt);
            }
        }));
    }

    for (auto& f : futures) {
        f.get();
    }
}

std::string ScanEngine::getCidr() const { return cidr_; }

std::vector<std::shared_ptr<HostStats>> ScanEngine::getActiveHosts() const {
    std::scoped_lock lock(hosts_mtx_);
    return active_hosts_;
}
