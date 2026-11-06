#pragma once

#include <string>
#include <vector>
#include <deque>
#include <optional>
#include <mutex>

class HostStats {
public:
    explicit HostStats(std::string ip_address, size_t max_history = 30);

    void addSample(std::optional<double> rtt_ms);
    void setOpenPorts(const std::vector<int>& ports);
    void setMacAddress(const std::string& mac);
    void setVendor(const std::string& vendor);
    void setHostname(const std::string& hostname);

    std::string getIp() const;
    std::string getMacAddress() const;
    std::string getVendor() const;
    std::string getHostname() const;
    std::vector<int> getOpenPorts() const;
    
    bool hasAnyRttSample() const;
    double getLastRtt() const;
    double getAverageRtt() const;
    double getJitter() const;
    double getPacketLoss() const;

private:
    std::string ip_;
    std::string mac_ = "LOCAL-INTERFACE";
    std::string vendor_ = "This Mac";
    std::string hostname_;
    size_t max_history_;

    std::deque<double> rtt_history_;
    std::deque<bool> delivery_history_;

    double last_rtt_ = -1.0;
    std::vector<int> open_ports_;

    mutable std::mutex mtx_;
};
