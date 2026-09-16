#pragma once

#include <cstdint>
#include <string>

namespace dlp {

enum class RiskLevel {
    Low,
    Medium,
    High,
    Critical
}; //[cite: 1]

inline const char* toString(RiskLevel level) { //[cite: 1]
    switch (level) {
        case RiskLevel::Low:      return "LOW";
        case RiskLevel::Medium:   return "MEDIUM";
        case RiskLevel::High:     return "HIGH";
        case RiskLevel::Critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

enum class FindingType {
    CreditCard,        
    KzIdNumber,         
    Password,           
    ApiKey,             
    PrivateKey,         
    HighEntropyBlock    
}; //[cite: 1]

inline const char* toString(FindingType type) { //[cite: 1]
    switch (type) {
        case FindingType::CreditCard:       return "Credit Card";
        case FindingType::KzIdNumber:       return "KZ IIN/BIN";
        case FindingType::Password:         return "Password";
        case FindingType::ApiKey:           return "API Key";
        case FindingType::PrivateKey:       return "Private Key";
        case FindingType::HighEntropyBlock: return "High-Entropy Region";
    }
    return "Unknown";
}

struct Finding { //[cite: 1]
    std::string filePath;
    uint64_t offset = 0;       
    uint64_t length = 0;       
    FindingType type = FindingType::HighEntropyBlock;
    RiskLevel risk = RiskLevel::Low;
    std::string maskedValue;   
    std::string rawValue;      // Хранит сырые данные для отправки в ИИ
    double entropy = 0.0;      
    std::string aiVerdict = "Не проверялось"; // Результат контекстного анализа Qwen
};

struct ScanConfig { //[cite: 1]
    std::string rootPath;                      
    unsigned threadCount = 0;                   
    size_t ioChunkSize = 1 * 1024 * 1024;        
    size_t entropyBlockSize = 256;               
    double entropyThreshold = 7.0;               
    std::string reportCsvPath;                   
    bool scanAllFiles = false;                   
    bool verbose = false;
    bool enableAi = true;                        // Флаг включения валидации ИИ
};

} // namespace dlp