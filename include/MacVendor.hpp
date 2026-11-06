#pragma once
#include <string>

class MacVendor {
public:
    static std::string normalizeMac(const std::string& raw_mac);
    static std::string lookupVendor(const std::string& normalized_mac);
};
