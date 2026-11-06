#pragma once

#include <string>
#include <vector>
#include <optional>
#include <map>

struct ProbeResult {
    bool host_alive = false;
    bool port_open = false;
    std::optional<double> rtt_ms;
};

class NetworkProber {
public:
    // Sonda TCP (SYN -> SYN-ACK lub RST)
    static ProbeResult probeTcpPort(const std::string& ip, int port, int timeout_ms = 120);

    // Sonda ICMP Echo without root privileges
    static std::optional<double> probeIcmp(const std::string& ip, int timeout_ms = 150);

    // Sending smalls UDP packets to get ARP requests
    static void triggerArpResolution(const std::string& ip);

    // Reading ARP
    static std::map<std::string, std::string> getSystemArpTable();

    // Get Host Name
    static std::string resolveHostname(const std::string& ip);

    // Automatically detects local subnet in CIDR format (e.g. "192.168.1.0/24") from active interface
    static std::string detectLocalCidr();
};
