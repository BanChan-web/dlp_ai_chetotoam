#include "AiAnalyzer.hpp"
#include <cstdio>
#include <array>
#include <fstream>
#include <iostream>
#include <thread>
#include <sstream>
#include <random>

#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#endif

namespace dlp {

static std::string escapeJson(const std::string& input) {
    std::string out;
    for (char c : input) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += " ";
        else if (c == '\r') out += " ";
        else if (c == '\t') out += " ";
        else out += c;
    }
    return out;
}

std::string AiAnalyzer::analyzeContext(const std::string& rawText, const std::string& findingType) {
    // Уникальный файл для каждого потока с генерацией ID
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<int> dist(100000, 999999);
    
    std::stringstream ss;
    ss << "req_" << std::this_thread::get_id() << "_" << dist(gen) << ".json";
    std::string reqFile = ss.str();

    std::ofstream out(reqFile);
    out << "{\n"
        << "  \"model\": \"qwen2.5:0.5b\",\n"
        << "  \"prompt\": \"Ты DLP-анализатор. Найдено подозрение на: " << escapeJson(findingType) 
        << ". Текст: '" << escapeJson(rawText) << "'. Это реальная утечка или тестовые данные? Ответь строго одним словом: LEAK или SAFE.\",\n"
        << "  \"stream\": false\n"
        << "}\n";
    out.close();

    std::string cmd = "curl -s http://localhost:11434/api/generate -H \"Content-Type: application/json\" -d @" + reqFile;
    
    std::array<char, 256> buffer;
    std::string response;

    FILE* pipe = popen(cmd.c_str(), "r");
    if (pipe) {
        while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
            response += buffer.data();
        }
        pclose(pipe);
    }
    
    std::remove(reqFile.c_str());

    if (response.find("LEAK") != std::string::npos) {
        return "ПОДТВЕРЖДЕНО (ИИ)";
    } else if (response.find("SAFE") != std::string::npos) {
        return "ЛОЖНОЕ СРАБАТЫВАНИЕ (ИИ)";
    }
    
    return "НЕОПРЕДЕЛЕНО (ИИ)";
}

} // namespace dlp