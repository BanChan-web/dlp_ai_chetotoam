#include "Signatures.hpp"
#include <regex>
#include <cctype>

namespace dlp {

std::string maskSensitive(const std::string& value, size_t keepStart, size_t keepEnd) { //[cite: 5]
    if (value.size() <= keepStart + keepEnd) { //[cite: 5]
        return std::string(value.size(), '*'); //[cite: 5]
    }
    std::string masked = value.substr(0, keepStart); //[cite: 5]
    masked.append(value.size() - keepStart - keepEnd, '*'); //[cite: 5]
    masked += value.substr(value.size() - keepEnd); //[cite: 5]
    return masked; //[cite: 5]
}

bool SignatureEngine::luhnCheck(const std::string& digitsOnly) { //[cite: 5]
    if (digitsOnly.empty()) return false; //[cite: 5]
    int sum = 0; //[cite: 5]
    bool alternate = false; //[cite: 5]
    for (auto it = digitsOnly.rbegin(); it != digitsOnly.rend(); ++it) { //[cite: 5]
        if (!std::isdigit(static_cast<unsigned char>(*it))) return false; //[cite: 5]
        int n = *it - '0'; //[cite: 5]
        if (alternate) { //[cite: 5]
            n *= 2; //[cite: 5]
            if (n > 9) n -= 9; //[cite: 5]
        }
        sum += n; //[cite: 5]
        alternate = !alternate; //[cite: 5]
    }
    return (sum % 10) == 0; //[cite: 5]
}

bool SignatureEngine::validateKazakhstanIdNumber(const std::string& d) { //[cite: 5]
    if (d.size() != 12) return false; //[cite: 5]
    for (char c : d) { //[cite: 5]
        if (!std::isdigit(static_cast<unsigned char>(c))) return false; //[cite: 5]
    }

    int month = (d[2] - '0') * 10 + (d[3] - '0'); //[cite: 5]
    int day   = (d[4] - '0') * 10 + (d[5] - '0'); //[cite: 5]
    if (month < 1 || month > 12) return false; //[cite: 5]
    if (day < 1 || day > 31) return false; //[cite: 5]

    int centuryDigit = d[6] - '0'; //[cite: 5]
    if (centuryDigit < 1 || centuryDigit > 6) return false; //[cite: 5]

    static const int w1[11] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}; //[cite: 5]
    static const int w2[11] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 1, 2}; //[cite: 5]

    auto weightedSum = [&](const int weights[11]) { //[cite: 5]
        int s = 0; //[cite: 5]
        for (int i = 0; i < 11; ++i) s += (d[i] - '0') * weights[i]; //[cite: 5]
        return s; //[cite: 5]
    };

    int control = weightedSum(w1) % 11; //[cite: 5]
    if (control == 10) { //[cite: 5]
        control = weightedSum(w2) % 11; //[cite: 5]
        if (control == 10) return false; //[cite: 5]
    }
    return control == (d[11] - '0'); //[cite: 5]
}

void SignatureEngine::findCreditCards(const std::string& text, uint64_t baseOffset,
                                       const std::string& filePath, std::vector<Finding>& out) const { //[cite: 5]
    static const std::regex cardRegex(R"((?:\d[ -]?){13,19})"); //[cite: 5]

    for (auto it = std::sregex_iterator(text.begin(), text.end(), cardRegex);
         it != std::sregex_iterator(); ++it) { //[cite: 5]
        std::string digits;
        digits.reserve(19);
        for (char c : it->str()) { //[cite: 5]
            if (std::isdigit(static_cast<unsigned char>(c))) digits += c; //[cite: 5]
        }
        if (digits.size() < 13 || digits.size() > 19) continue; //[cite: 5]
        if (!luhnCheck(digits)) continue; //[cite: 5]

        Finding f; //[cite: 5]
        f.filePath = filePath; //[cite: 5]
        f.offset = baseOffset + static_cast<uint64_t>(it->position()); //[cite: 5]
        f.length = digits.size(); //[cite: 5]
        f.type = FindingType::CreditCard; //[cite: 5]
        f.risk = RiskLevel::Critical; //[cite: 5]
        f.maskedValue = maskSensitive(digits, 0, 4); //[cite: 5]
        f.rawValue = digits; // Сохраняем оригинальное значение для ИИ
        out.push_back(std::move(f)); //[cite: 5]
    }
}

void SignatureEngine::findKzIdNumbers(const std::string& text, uint64_t baseOffset,
                                       const std::string& filePath, std::vector<Finding>& out) const { //[cite: 5]
    static const std::regex idRegex(R"(\b\d{12}\b)"); //[cite: 5]

    for (auto it = std::sregex_iterator(text.begin(), text.end(), idRegex);
         it != std::sregex_iterator(); ++it) { //[cite: 5]
        std::string digits = it->str(); //[cite: 5]
        if (!validateKazakhstanIdNumber(digits)) continue; //[cite: 5]

        Finding f; //[cite: 5]
        f.filePath = filePath; //[cite: 5]
        f.offset = baseOffset + static_cast<uint64_t>(it->position()); //[cite: 5]
        f.length = 12; //[cite: 5]
        f.type = FindingType::KzIdNumber; //[cite: 5]
        f.risk = RiskLevel::High; //[cite: 5]
        f.maskedValue = maskSensitive(digits, 0, 4); //[cite: 5]
        f.rawValue = digits; // Сохраняем оригинальное значение для ИИ
        out.push_back(std::move(f)); //[cite: 5]
    }
}

void SignatureEngine::findSecrets(const std::string& text, uint64_t baseOffset,
                                   const std::string& filePath, std::vector<Finding>& out) const { //[cite: 5]
    struct Rule {
        std::regex pattern;
        FindingType type;
        RiskLevel risk;
    }; //[cite: 5]

    static const std::vector<Rule> rules = [] { //[cite: 5]
        std::vector<Rule> r;
        r.push_back({ std::regex(R"(-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)"),
                       FindingType::PrivateKey, RiskLevel::Critical }); //[cite: 5]
        r.push_back({ std::regex(R"(AKIA[0-9A-Z]{16})"),
                       FindingType::ApiKey, RiskLevel::Critical }); //[cite: 5]
        r.push_back({ std::regex(R"((?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9_-]{16,}['"]?)",
                       std::regex::icase),
                       FindingType::ApiKey, RiskLevel::High }); //[cite: 5]
        r.push_back({ std::regex(R"((?:password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]{6,}['"]?)",
                       std::regex::icase),
                       FindingType::Password, RiskLevel::High }); //[cite: 5]
        return r;
    }();

    for (const auto& rule : rules) { //[cite: 5]
        for (auto it = std::sregex_iterator(text.begin(), text.end(), rule.pattern);
             it != std::sregex_iterator(); ++it) { //[cite: 5]
            Finding f; //[cite: 5]
            f.filePath = filePath; //[cite: 5]
            f.offset = baseOffset + static_cast<uint64_t>(it->position()); //[cite: 5]
            f.length = it->str().size(); //[cite: 5]
            f.type = rule.type; //[cite: 5]
            f.risk = rule.risk; //[cite: 5]
            f.maskedValue = maskSensitive(it->str(), 3, 3); //[cite: 5]
            f.rawValue = it->str(); // Сохраняем сырой фрагмент ключа/пароля
            out.push_back(std::move(f)); //[cite: 5]
        }
    }
}

std::vector<Finding> SignatureEngine::scan(const std::string& text, uint64_t baseOffset,
                                            const std::string& filePath) const { //[cite: 5]
    std::vector<Finding> out; //[cite: 5]
    findCreditCards(text, baseOffset, filePath, out); //[cite: 5]
    findKzIdNumbers(text, baseOffset, filePath, out); //[cite: 5]
    findSecrets(text, baseOffset, filePath, out); //[cite: 5]
    return out; //[cite: 5]
}

} // namespace dlp