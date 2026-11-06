#include "ScanEngine.hpp"
#include "NetworkProber.hpp"
#include "DashboardTUI.hpp"

#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

std::atomic<bool> keep_running{true};

void signalHandler(int) {
    keep_running = false;
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signalHandler);

    std::string target_cidr = (argc > 1) ? argv[1] : NetworkProber::detectLocalCidr();

    ScanEngine engine(target_cidr);
    std::cout << "\033[1;36m[*] Automatycznie wykryty zakres sieci: " << engine.getCidr() << "\033[0m\n";
    std::cout << "[*] Trwa hybrydowy skan (ARP + ICMP + 16 kluczowych portow TCP)...\n";

    engine.discoverHosts(120);

    auto hosts = engine.getActiveHosts();
    if (hosts.empty()) {
        std::cout << "\033[31m[!] Nie wykryto zadnych aktywnych hostow w sieci " << engine.getCidr() << ".\033[0m\n";
        return 0;
    }

    DashboardTUI::hideCursor();
    int tick = 1;

    while (keep_running) {
        DashboardTUI::render(engine.getCidr(), engine.getActiveHosts(), tick);
        
        for (int i = 0; i < 8 && keep_running; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (!keep_running) break;
        if (tick % 30 == 0) {
            engine.refreshTopology(100);
        }

        engine.pingActiveHosts(200);
        tick++;
    }

    DashboardTUI::showCursor();
    std::cout << "\n\033[32m[OK] Zatrzymano monitorowanie. Kursor przywrocony.\033[0m\n";
    return 0;
}
