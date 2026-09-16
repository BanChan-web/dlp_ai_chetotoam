#include <iostream>
#include <chrono>
#include "Scanner.hpp"
#include "Common.hpp"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Использование: ./dlp_scanner <путь_к_папке>\n";
        return 1;
    }

    dlp::ScanConfig config;
    config.rootPath = argv[1];
    config.threadCount = 0; // Использовать все доступные ядра CPU
    config.enableAi = true; // Фильтрация через Ollama Qwen2.5

    std::cout << "=======================================================\n";
    std::cout << "    HYBRID DLP SCANNER (C++ Core + Ollama AI Engine)   \n";
    std::cout << "=======================================================\n";
    std::cout << "[*] Запуск многопоточного анализа папки: " << config.rootPath << "\n\n";

    auto start = std::chrono::high_resolution_clock::now();

    dlp::Scanner scanner(config);
    auto results = scanner.run();

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    std::cout << "=== РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ ===\n";
    for (const auto& f : results) {
        std::cout << "[!] Тип: " << dlp::toString(f.type) 
                  << " | Уровень риска: " << dlp::toString(f.risk) << "\n"
                  << "    Файл: " << f.filePath << "\n"
                  << "    Маска: " << f.maskedValue << "\n"
                  << "    Вердикт ИИ (Qwen): " << f.aiVerdict << "\n"
                  << "    ---------------------------------------------------\n";
    }

    std::cout << "\n Сканирование завершено за " << elapsed.count() << " сек.\n";
    std::cout << " Всего зафиксировано аномалий: " << results.size() << "\n";

    return 0;
}