#include "HostStats.hpp"
#include "MacVendor.hpp"
#include "NetworkProber.hpp"
#include <iostream>
#include <cassert>
#include <cmath>

bool isClose(double a, double b, double epsilon = 0.01) {
    return std::abs(a - b) < epsilon;
}

int main() {
    std::cout << "=== URUCHAMIANIE TESTOW JEDNOSTKOWYCH NETRADAR ===\n";

    // 1. Test obliczeń RTT, Jittera i Packet Loss
    HostStats host("192.168.1.1", 5);
    assert(!host.hasAnyRttSample());
    host.addSample(10.0);
    host.addSample(20.0);
    host.addSample(10.0);
    host.addSample(std::nullopt);

    assert(host.hasAnyRttSample());
    assert(isClose(host.getAverageRtt(), 13.33));
    assert(isClose(host.getJitter(), 10.0));
    assert(isClose(host.getPacketLoss(), 25.0));
    std::cout << "[OK] Test 1: Matematyka sieciowa (RTT / Jitter / Loss)\n";

    // 2. Test normalizacji adresów MAC z systemu macOS
    std::string raw_mac = "2:9d:2:4a:b:94";
    std::string norm_mac = MacVendor::normalizeMac(raw_mac);
    assert(norm_mac == "02:9D:02:4A:0B:94");
    assert(MacVendor::lookupVendor(norm_mac) == "Private-WiFi");
    assert(MacVendor::lookupVendor("64:D1:54:11:22:33") == "MikroTik");
    std::cout << "[OK] Test 2: Normalizacja MAC i detekcja OUI / Private-WiFi\n";

    // 3. Test auto-detekcji podsieci CIDR
    std::string cidr = NetworkProber::detectLocalCidr();
    assert(cidr.find('/') != std::string::npos);
    std::cout << "[OK] Test 3: Auto-detekcja interfejsu CIDR (" << cidr << ")\n";

    std::cout << "\n[SUKCES] Wszystkie testy jednostkowe zakonczone pomyslnie!\n";
    return 0;
}
