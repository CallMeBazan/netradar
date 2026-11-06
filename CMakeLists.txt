cmake_minimum_required(VERSION 3.15)
project(netradar VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Flagi optymalizacji i ostrzeżeń kompilatora
add_compile_options(-Wall -Wextra -O2)

include_directories(include)

# Główny plik wykonywalny: netradar
add_executable(netradar
    src/main.cpp
    src/HostStats.cpp
    src/NetworkProber.cpp
    src/ScanEngine.cpp
    src/MacVendor.cpp
    src/DashboardTUI.cpp
)

# Plik wykonywalny testów jednostkowych: run_tests
add_executable(run_tests
    tests/test_stats.cpp
    src/HostStats.cpp
    src/NetworkProber.cpp
    src/MacVendor.cpp
)
