#include "HostStats.hpp"
#include <numeric>
#include <cmath>
#include <algorithm>

HostStats::HostStats(std::string ip_address, size_t max_history)
    : ip_(std::move(ip_address)), max_history_(max_history) {}

void HostStats::addSample(std::optional<double> rtt_ms) {
    std::scoped_lock lock(mtx_);

    if (rtt_ms.has_value()) {
        double val = rtt_ms.value();
        last_rtt_ = val;
        rtt_history_.push_back(val);
        if (rtt_history_.size() > max_history_) {
            rtt_history_.pop_front();
        }
        delivery_history_.push_back(true);
    } else {
        last_rtt_ = -1.0;
        delivery_history_.push_back(false);
    }

    if (delivery_history_.size() > max_history_) {
        delivery_history_.pop_front();
    }
}

void HostStats::setOpenPorts(const std::vector<int>& ports) {
    std::scoped_lock lock(mtx_);
    open_ports_ = ports;
}

void HostStats::setMacAddress(const std::string& mac) {
    std::scoped_lock lock(mtx_);
    mac_ = mac;
}

void HostStats::setVendor(const std::string& vendor) {
    std::scoped_lock lock(mtx_);
    vendor_ = vendor;
}

void HostStats::setHostname(const std::string& hostname) {
    std::scoped_lock lock(mtx_);
    hostname_ = hostname;
}

std::string HostStats::getIp() const {
    std::scoped_lock lock(mtx_);
    return ip_;
}

std::string HostStats::getMacAddress() const {
    std::scoped_lock lock(mtx_);
    return mac_;
}

std::string HostStats::getVendor() const {
    std::scoped_lock lock(mtx_);
    return vendor_;
}

std::string HostStats::getHostname() const {
    std::scoped_lock lock(mtx_);
    return hostname_;
}

std::vector<int> HostStats::getOpenPorts() const {
    std::scoped_lock lock(mtx_);
    return open_ports_;
}

bool HostStats::hasAnyRttSample() const {
    std::scoped_lock lock(mtx_);
    return !rtt_history_.empty();
}

double HostStats::getLastRtt() const {
    std::scoped_lock lock(mtx_);
    return last_rtt_;
}

double HostStats::getAverageRtt() const {
    std::scoped_lock lock(mtx_);
    if (rtt_history_.empty()) return 0.0;
    double sum = std::accumulate(rtt_history_.begin(), rtt_history_.end(), 0.0);
    return sum / static_cast<double>(rtt_history_.size());
}

double HostStats::getJitter() const {
    std::scoped_lock lock(mtx_);
    if (rtt_history_.size() < 2) return 0.0;

    double diff_sum = 0.0;
    for (size_t i = 1; i < rtt_history_.size(); ++i) {
        diff_sum += std::abs(rtt_history_[i] - rtt_history_[i - 1]);
    }
    return diff_sum / static_cast<double>(rtt_history_.size() - 1);
}

double HostStats::getPacketLoss() const {
    std::scoped_lock lock(mtx_);
    if (delivery_history_.empty()) return 0.0;

    size_t lost_count = std::count(delivery_history_.begin(), delivery_history_.end(), false);
    return (static_cast<double>(lost_count) / static_cast<double>(delivery_history_.size())) * 100.0;
}
