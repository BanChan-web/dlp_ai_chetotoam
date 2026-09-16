#pragma once
#include <string>

namespace dlp {

class AiAnalyzer {
public:
    // Функция проверки текста через локальный API Ollama (Qwen2.5)
    static std::string analyzeContext(const std::string& rawText, const std::string& findingType);
};

} // namespace dlp