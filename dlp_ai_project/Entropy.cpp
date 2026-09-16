#include "Entropy.hpp"
#include <array>
#include <cmath>

namespace dlp {

double EntropyCalculator::calculate(const uint8_t* data, size_t length) { //[cite: 3]
    if (data == nullptr || length == 0) return 0.0; //[cite: 3]

    std::array<uint64_t, 256> freq{}; //[cite: 3]
    for (size_t i = 0; i < length; ++i) { //[cite: 3]
        ++freq[data[i]]; //[cite: 3]
    }

    const double total = static_cast<double>(length); //[cite: 3]
    double entropy = 0.0; //[cite: 3]

    for (uint64_t count : freq) { //[cite: 3]
        if (count == 0) continue; //[cite: 3]
        double p = static_cast<double>(count) / total; //[cite: 3]
        entropy -= p * std::log2(p); //[cite: 3]
    }

    return entropy; //[cite: 3]
}

} // namespace dlp