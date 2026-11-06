#include "DashboardTUI.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

namespace Color {
    const std::string RESET   = "\033[0m";
    const std::string BOLD    = "\033[1m";
    const std::string DIM     = "\033[2m";
    const std::string GREEN   = "\033[32m";
    const std::string YELLOW  = "\033[33m";
    const std::string RED     = "\033[31m";
    const std::string CYAN    = "\033[36m";
    const std::string MAGENTA = "\033[35m";
}

void DashboardTUI::hideCursor() { std::cout << "\033[?25l" << std::flush; }
void DashboardTUI::showCursor() { std::cout << "\033[?25h" << std::flush; }

std::string DashboardTUI::formatPortName(int port) {
    switch (port) {
        case 21:    return "21(FTP)";
        case 22:    return "22(SSH)";
        case 23:    return "\033[31m23(TELNET!)\033[36m";
        case 53:    return "53(DNS)";
        case 80:    return "80(HTTP)";
        case 443:   return "443(HTTPS)";
        case 445:   return "445(SMB)";
        case 554:   return "554(RTSP-Cam)";
        case 1883:  return "1883(MQTT)";
        case 3389:  return "3389(RDP)";
        case 8080:  return "8080(HTTP-Alt)";
        case 8291:  return "8291(WinBox)";
        case 8443:  return "8443(HTTPS-Alt)";
        case 8728:  return "8728(ROS-API)";
        case 9100:  return "9100(Printer)";
        case 62078: return "62078(Apple)";
        default:    return std::to_string(port);
    }
}

std::string DashboardTUI::colorizeRtt(double rtt_ms) {
    if (rtt_ms < 0) return Color::DIM + "STEALTH     " + Color::RESET;
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << rtt_ms << " ms";
    std::string text = oss.str();
    while (text.length() < 12) text += " ";

    if (rtt_ms < 10.0) return Color::GREEN + text + Color::RESET;
    if (rtt_ms < 50.0) return Color::YELLOW + text + Color::RESET;
    return Color::RED + text + Color::RESET;
}

std::string DashboardTUI::colorizeJitter(double jitter_ms) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << jitter_ms << " ms";
    std::string text = oss.str();
    while (text.length() < 11) text += " ";

    if (jitter_ms < 3.0)  return Color::GREEN + text + Color::RESET;
    if (jitter_ms < 15.0) return Color::YELLOW + text + Color::RESET;
    return Color::RED + text + Color::RESET;
}

std::string DashboardTUI::colorizeLoss(double loss_pct) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(0) << loss_pct << "%";
    std::string text = oss.str();
    while (text.length() < 7) text += " ";

    if (loss_pct == 0.0) return Color::GREEN + text + Color::RESET;
    if (loss_pct < 15.0) return Color::YELLOW + text + Color::RESET;
    return Color::RED + text + Color::RESET;
}

std::string DashboardTUI::buildHealthBar(double rtt_ms, double jitter_ms, double loss_pct) {
    int score = 10;
    if (rtt_ms < 0) score -= 4;
    else if (rtt_ms > 50.0) score -= 3;
    else if (rtt_ms > 15.0) score -= 1;

    if (jitter_ms > 20.0) score -= 3;
    else if (jitter_ms > 5.0) score -= 1;

    if (loss_pct > 0.0) score -= static_cast<int>(loss_pct / 15.0) + 1;
    if (score < 0) score = 0;

    std::string bar_color = Color::GREEN;
    if (score <= 4) bar_color = Color::RED;
    else if (score <= 7) bar_color = Color::YELLOW;

    std::string bar = "[";
    for (int i = 0; i < 10; ++i) bar += (i < score) ? "#" : ".";
    bar += "]";
    return bar_color + bar + Color::RESET + "  ";
}

void DashboardTUI::render(const std::string& cidr,
                          const std::vector<std::shared_ptr<HostStats>>& hosts,
                          int tick_count) {
    std::cout << "\033[2J\033[H";

    int next_refresh = 30 - (tick_count % 30);

    std::cout << Color::BOLD << Color::CYAN
              << "===============================================================================================================================\n"
              << "  NETRADAR - HYBRID LAN AUDITOR  |  Siec: " << cidr
              << "  |  Hosty: " << hosts.size()
              << "  |  Cykl: #" << tick_count
              << " (Auto-Discovery za: " << next_refresh << "s)\n"
              << "===============================================================================================================================\n"
              << Color::RESET;

    std::cout << Color::BOLD
              << std::left << std::setw(5)  << "ID"
              << std::setw(15) << "ADRES IP"
              << std::setw(19) << "ADRES MAC"
              << std::setw(14) << "VENDOR / TYP"
              << std::setw(12) << "LAST PING"
              << std::setw(12) << "AVG PING"
              << std::setw(11) << "JITTER"
              << std::setw(7)  << "LOSS"
              << std::setw(14) << "STABILNOSC"
              << "USLUGI / HOSTNAME\n"
              << Color::RESET;

    std::cout << Color::DIM
              << "-------------------------------------------------------------------------------------------------------------------------------\n"
              << Color::RESET;

    int id = 1;
    for (const auto& h : hosts) {
        bool has_rtt    = h->hasAnyRttSample();
        double last_rtt = h->getLastRtt();
        double avg_rtt  = h->getAverageRtt();
        double jitter   = h->getJitter();
        double loss     = h->getPacketLoss();

        std::cout << Color::DIM << std::left << std::setw(5) << id++ << Color::RESET
                  << std::left << std::setw(15) << h->getIp()
                  << std::setw(19) << h->getMacAddress()
                  << Color::MAGENTA << std::setw(14) << h->getVendor() << Color::RESET;

        if (!has_rtt) {
            std::cout << Color::DIM
                      << std::setw(12) << "STEALTH"
                      << std::setw(12) << "-     "
                      << std::setw(11) << "-     "
                      << std::setw(7)  << "-  "
                      << std::setw(14) << "[ARP-ONLY]  "
                      << Color::RESET;
        } else {
            std::cout << colorizeRtt(last_rtt)
                      << colorizeRtt(avg_rtt)
                      << colorizeJitter(jitter)
                      << colorizeLoss(loss)
                      << buildHealthBar(last_rtt, jitter, loss);
        }

        auto ports = h->getOpenPorts();
        std::string hname = h->getHostname();

        if (!ports.empty()) {
            for (int p : ports) {
                std::cout << Color::CYAN << formatPortName(p) << " " << Color::RESET;
            }
        } else {
            std::cout << Color::DIM << "L2/L3 Active " << Color::RESET;
        }

        if (!hname.empty() && hname != h->getIp()) {
            std::cout << Color::YELLOW << "(" << hname << ")" << Color::RESET;
        }
        std::cout << "\n";
    }

    std::cout << Color::DIM
              << "-------------------------------------------------------------------------------------------------------------------------------\n"
              << "Wcisnij [Ctrl+C] aby zakonczyc monitorowanie. Nowe urzadzenia w sieci sa wykrywane automatycznie co 30 cykli.\n"
              << Color::RESET << std::flush;
}
