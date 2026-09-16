#pragma once
#include <cstddef>
#include <cstdint>

namespace dlp {

class EntropyCalculator { //[cite: 2]
public:
    static double calculate(const uint8_t* data, size_t length); //[cite: 2]
};

} // namespace dlp