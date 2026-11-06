#pragma once

#include "HostStats.hpp"
#include <string>
#include <vector>
#include <memory>
#include <mutex>

class ScanEngine {
public:
    explicit ScanEngine(const std::string& cidr_or_subnet);

    // First full scanning
    void discoverHosts(int timeout_ms = 120);

    // Seamless background refresh of new hosts
    size_t refreshTopology(int timeout_ms = 100);

    // Polling active hosts in each cycle
    void pingActiveHosts(int timeout_ms = 200);

    std::string getCidr() const;
    std::vector<std::shared_ptr<HostStats>> getActiveHosts() const;

private:
    std::string cidr_;
    std::vector<std::string> target_ips_;
    std::vector<int> target_ports_;
    std::vector<std::shared_ptr<HostStats>> active_hosts_;
    mutable std::mutex hosts_mtx_;

    void parseCidrRange(const std::string& input);
    std::shared_ptr<HostStats> profileSingleHost(const std::string& ip, bool in_arp, const std::string& raw_mac, int timeout_ms);
};
