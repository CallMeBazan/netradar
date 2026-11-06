#include "MacVendor.hpp"
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <algorithm>
#include <cctype>

std::string MacVendor::normalizeMac(const std::string& raw_mac) {
    if (raw_mac.empty() || raw_mac.find(':') == std::string::npos) return raw_mac;
    std::stringstream ss(raw_mac);
    std::string segment;
    std::ostringstream result;
    bool first = true;
    while (std::getline(ss, segment, ':')) {
        if (!first) result << ":";
        first = false;
        if (segment.length() == 1) result << '0';
        for (char c : segment) result << static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return result.str();
}

std::string MacVendor::lookupVendor(const std::string& mac) {
    if (mac.length() < 8 || mac.find(':') == std::string::npos) return "";
    std::string prefix = mac.substr(0, 8);
    static const std::unordered_map<std::string, std::string> oui_db = {
        {"4C:5E:0C", "MikroTik"}, {"64:D1:54", "MikroTik"}, {"B8:69:F4", "MikroTik"},
        {"24:5A:4C", "Ubiquiti"}, {"74:83:C2", "Ubiquiti"}, {"00:1B:54", "Cisco"},
        {"3C:58:5D", "Router/ISP"}, {"3C:E3:6B", "NetDevice"}, {"A8:31:62", "WiFi-Node"},
        {"F0:18:98", "Apple"},    {"A4:83:E7", "Apple"},    {"B8:27:EB", "RaspberryPi"},
        {"24:0A:C4", "Espressif"}, {"E4:FA:C4", "Client/PC"}, {"BE:88:FA", "Mobile/WiFi"}
    };
    auto it = oui_db.find(prefix);
    if (it != oui_db.end()) return it->second;
    char second_char = mac[1];
    if (second_char == '2' || second_char == '6' || second_char == 'A' || second_char == 'E') {
        return "Private-WiFi";
    }
    return "Standard-OUI";
}
