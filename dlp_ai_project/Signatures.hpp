#pragma once
#include <string>
#include <vector>
#include "Common.hpp"

namespace dlp {

std::string maskSensitive(const std::string& value, size_t keepStart, size_t keepEnd); //[cite: 4]

class SignatureEngine { //[cite: 4]
public:
    std::vector<Finding> scan(const std::string& text,
                               uint64_t baseOffset,
                               const std::string& filePath) const; //[cite: 4]

    static bool luhnCheck(const std::string& digitsOnly); //[cite: 4]
    static bool validateKazakhstanIdNumber(const std::string& twelveDigits); //[cite: 4]

private:
    void findCreditCards(const std::string& text, uint64_t baseOffset,
                          const std::string& filePath, std::vector<Finding>& out) const; //[cite: 4]
    void findKzIdNumbers(const std::string& text, uint64_t baseOffset,
                          const std::string& filePath, std::vector<Finding>& out) const; //[cite: 4]
    void findSecrets(const std::string& text, uint64_t baseOffset,
                      const std::string& filePath, std::vector<Finding>& out) const; //[cite: 4]
};

} // namespace dlp