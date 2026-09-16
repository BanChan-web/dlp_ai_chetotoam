#pragma once
#include <vector>
#include <string>
#include "Common.hpp"

namespace dlp {

class Scanner { //[cite: 6]
public:
    explicit Scanner(const ScanConfig& config); //[cite: 6]
    std::vector<Finding> run() const; //[cite: 6]

private:
    ScanConfig config_; //[cite: 6]
    std::vector<std::string> collectFiles() const; //[cite: 6]
    std::vector<Finding> scanFile(const std::string& path) const; //[cite: 6]
};

} // namespace dlp