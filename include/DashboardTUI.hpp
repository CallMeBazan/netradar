#pragma once

#include "HostStats.hpp"
#include <vector>
#include <memory>
#include <string>

class DashboardTUI {
public:
    static void render(const std::string& subnet,
                       const std::vector<std::shared_ptr<HostStats>>& hosts,
                       int tick_count);
    static void hideCursor();
    static void showCursor();

private:
    static std::string formatPortName(int port);
    static std::string colorizeRtt(double rtt_ms);
    static std::string colorizeJitter(double jitter_ms);
    static std::string colorizeLoss(double loss_pct);
    static std::string buildHealthBar(double rtt_ms, double jitter_ms, double loss_pct);
};
