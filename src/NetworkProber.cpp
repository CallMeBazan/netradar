#include "NetworkProber.hpp"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <regex>

static uint16_t computeIcmpChecksum(void* b, int len) {
    uint16_t* buf = static_cast<uint16_t*>(b);
    uint32_t sum = 0;
    for (; len > 1; len -= 2) sum += *buf++;
    if (len == 1) sum += *reinterpret_cast<uint8_t*>(buf);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

ProbeResult NetworkProber::probeTcpPort(const std::string& ip, int port, int timeout_ms) {
    ProbeResult result;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return result;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        return result;
    }

    auto start_time = std::chrono::high_resolution_clock::now();
    int res = connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

    if (res == 0) {
        auto end_time = std::chrono::high_resolution_clock::now();
        result.host_alive = true;
        result.port_open = true;
        result.rtt_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
        close(sock);
        return result;
    }

    if (errno != EINPROGRESS) {
        close(sock);
        return result;
    }

    pollfd pfd{};
    pfd.fd = sock;
    pfd.events = POLLOUT;

    int poll_res = poll(&pfd, 1, timeout_ms);
    auto end_time = std::chrono::high_resolution_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

    if (poll_res > 0) {
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);

        if (so_error == 0) {
            result.host_alive = true;
            result.port_open = true;
            result.rtt_ms = elapsed_ms;
        } else if (so_error == ECONNREFUSED) {
            result.host_alive = true;
            result.port_open = false;
            result.rtt_ms = elapsed_ms;
        }
    }

    close(sock);
    return result;
}

std::optional<double> NetworkProber::probeIcmp(const std::string& ip, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) return std::nullopt;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        return std::nullopt;
    }

    icmp packet{};
    packet.icmp_type = ICMP_ECHO;
    packet.icmp_code = 0;
    packet.icmp_id = htons(static_cast<uint16_t>(getpid() & 0xFFFF));
    packet.icmp_seq = htons(1);
    packet.icmp_cksum = computeIcmpChecksum(&packet, sizeof(packet));

    auto start_time = std::chrono::high_resolution_clock::now();
    if (sendto(sock, &packet, sizeof(packet), 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) <= 0) {
        close(sock);
        return std::nullopt;
    }

    pollfd pfd{};
    pfd.fd = sock;
    pfd.events = POLLIN;

    int poll_res = poll(&pfd, 1, timeout_ms);
    if (poll_res > 0) {
        uint8_t recv_buf[1024];
        sockaddr_in from{};
        socklen_t from_len = sizeof(from);
        ssize_t bytes = recvfrom(sock, recv_buf, sizeof(recv_buf), 0, reinterpret_cast<struct sockaddr*>(&from), &from_len);
        auto end_time = std::chrono::high_resolution_clock::now();

        if (bytes > 0 && from.sin_addr.s_addr == addr.sin_addr.s_addr) {
            close(sock);
            return std::chrono::duration<double, std::milli>(end_time - start_time).count();
        }
    }

    close(sock);
    return std::nullopt;
}

void NetworkProber::triggerArpResolution(const std::string& ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5353); // Port mDNS
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    const char dummy = 0;
    sendto(sock, &dummy, 1, 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    close(sock);
}

std::map<std::string, std::string> NetworkProber::getSystemArpTable() {
    std::map<std::string, std::string> arp_map;
    FILE* pipe = popen("arp -an", "r");
    if (!pipe) return arp_map;

    char line[256];
    std::regex arp_regex(R"(\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+))");

    while (fgets(line, sizeof(line), pipe) != nullptr) {
        std::string str_line(line);
        if (str_line.find("incomplete") != std::string::npos) continue;

        std::smatch match;
        if (std::regex_search(str_line, match, arp_regex) && match.size() == 3) {
            std::string ip = match[1].str();
            std::string mac = match[2].str();
            if (mac != "ff:ff:ff:ff:ff:ff") {
                arp_map[ip] = mac;
            }
        }
    }
    pclose(pipe);
    return arp_map;
}

std::string NetworkProber::resolveHostname(const std::string& ip) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    char host[NI_MAXHOST];
    if (getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa), host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) {
        return std::string(host);
    }
    return "";
}

std::string NetworkProber::detectLocalCidr() {
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) return "192.168.1.0/24";

    std::string result_cidr = "192.168.1.0/24";

    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;

        std::string if_name(ifa->ifa_name);
        if (if_name == "lo0" || if_name.find("utun") == 0) continue;

        auto* addr = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
        auto* mask = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_netmask);

        uint32_t ip_val = ntohl(addr->sin_addr.s_addr);
        uint32_t mask_val = ntohl(mask->sin_addr.s_addr);

        if ((ip_val >> 16) == 0xA9FE) continue;

        uint32_t net_val = ip_val & mask_val;
        int prefix_len = 0;
        uint32_t temp_mask = mask_val;
        while (temp_mask & 0x80000000) {
            prefix_len++;
            temp_mask <<= 1;
        }

        in_addr net_addr{};
        net_addr.s_addr = htonl(net_val);
        char net_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &net_addr, net_str, INET_ADDRSTRLEN);

        result_cidr = std::string(net_str) + "/" + std::to_string(prefix_len);
        break; 
    }

    freeifaddrs(ifaddr);
    return result_cidr;
}
