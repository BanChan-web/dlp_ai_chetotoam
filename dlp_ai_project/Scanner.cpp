#include "Scanner.hpp"
#include "Entropy.hpp"
#include "Signatures.hpp"
#include "AiAnalyzer.hpp"

#include <filesystem>
#include <fstream>
#include <thread>
#include <atomic>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

namespace dlp {

namespace {

bool hasSkippedExtension(const fs::path& p) { //[cite: 7]
    static const std::vector<std::string> skipExt = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".tiff",
        ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav", ".flac", ".ogg", ".webm",
        ".zip", ".rar", ".7z", ".gz", ".tar", ".bz2", ".xz",
        ".exe", ".dll", ".msi", ".so", ".class", ".pyc",
        ".ttf", ".otf", ".woff", ".woff2"
    }; //[cite: 7]
    std::string ext = p.extension().string(); //[cite: 7]
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); }); //[cite: 7]
    return std::find(skipExt.begin(), skipExt.end(), ext) != skipExt.end(); //[cite: 7]
}

} // namespace

Scanner::Scanner(const ScanConfig& config) : config_(config) {} //[cite: 7]

std::vector<std::string> Scanner::collectFiles() const { //[cite: 7]
    std::vector<std::string> files; //[cite: 7]
    std::error_code ec; //[cite: 7]

    fs::path root(config_.rootPath); //[cite: 7]

    if (fs::is_regular_file(root, ec)) { //[cite: 7]
        files.push_back(root.string()); //[cite: 7]
        return files; //[cite: 7]
    }

    fs::recursive_directory_iterator it(
        root, fs::directory_options::skip_permission_denied, ec); //[cite: 7]
    fs::recursive_directory_iterator endIt; //[cite: 7]

    if (ec) return files; //[cite: 7]

    while (it != endIt) { //[cite: 7]
        std::error_code fileEc;
        const fs::directory_entry& entry = *it;

        if (entry.is_regular_file(fileEc) && !fileEc) { //[cite: 7]
            if (config_.scanAllFiles || !hasSkippedExtension(entry.path())) { //[cite: 7]
                files.push_back(entry.path().string()); //[cite: 7]
            }
        }

        it.increment(ec); //[cite: 7]
        if (ec) break; //[cite: 7]
    }

    return files; //[cite: 7]
}

std::vector<Finding> Scanner::scanFile(const std::string& path) const { //[cite: 7]
    std::vector<Finding> findings; //[cite: 7]
    std::ifstream in(path, std::ios::binary); //[cite: 7]
    if (!in) return findings; //[cite: 7]

    static thread_local SignatureEngine engine; //[cite: 7]

    const size_t blockSize = std::max<size_t>(1, config_.entropyBlockSize); //[cite: 7]
    const size_t ioSize = std::max<size_t>(config_.ioChunkSize, blockSize); //[cite: 7]
    std::vector<char> ioBuf(ioSize); //[cite: 7]

    std::string pending;      //[cite: 7]
    size_t consumedPos = 0;   //[cite: 7]

    std::string textSegment; //[cite: 7]
    uint64_t textSegmentStart = 0; //[cite: 7]
    bool inTextSegment = false; //[cite: 7]

    uint64_t entropyRegionStart = 0; //[cite: 7]
    uint64_t entropyRegionLen = 0; //[cite: 7]
    double entropyRegionMax = 0.0; //[cite: 7]
    bool inEntropyRegion = false; //[cite: 7]

    const size_t maxSegmentSize = 8 * 1024 * 1024; //[cite: 7]
    const size_t keepOverlap = 128;                //[cite: 7]

    uint64_t fileOffset = 0; //[cite: 7]

    auto flushTextSegment = [&]() {
        if (inTextSegment && !textSegment.empty()) {
            auto found = engine.scan(textSegment, textSegmentStart, path); //[cite: 7]
            for (auto& f : found) {
                // Если включен ИИ и найден конкретный секрет — отправляем в Qwen
                if (config_.enableAi && !f.rawValue.empty()) {
                    f.aiVerdict = AiAnalyzer::analyzeContext(f.rawValue, toString(f.type));
                }
                findings.push_back(std::move(f)); //[cite: 7]
            }
        }
        textSegment.clear(); //[cite: 7]
        inTextSegment = false; //[cite: 7]
    };

    auto flushEntropyRegion = [&]() {
        if (inEntropyRegion && entropyRegionLen > 0) { //[cite: 7]
            Finding f; //[cite: 7]
            f.filePath = path; //[cite: 7]
            f.offset = entropyRegionStart; //[cite: 7]
            f.length = entropyRegionLen; //[cite: 7]
            f.type = FindingType::HighEntropyBlock; //[cite: 7]
            f.risk = RiskLevel::Medium; //[cite: 7]
            f.entropy = entropyRegionMax; //[cite: 7]
            f.aiVerdict = "Зашифрованный блок";
            findings.push_back(std::move(f)); //[cite: 7]
        }
        inEntropyRegion = false; //[cite: 7]
        entropyRegionLen = 0; //[cite: 7]
        entropyRegionMax = 0.0; //[cite: 7]
    };

    bool eof = false; //[cite: 7]
    while (true) {
        size_t available = pending.size() - consumedPos; //[cite: 7]

        if (available < blockSize && !eof) { //[cite: 7]
            if (consumedPos > 0) { //[cite: 7]
                pending.erase(0, consumedPos); //[cite: 7]
                consumedPos = 0; //[cite: 7]
            }
            in.read(ioBuf.data(), static_cast<std::streamsize>(ioBuf.size())); //[cite: 7]
            std::streamsize got = in.gcount(); //[cite: 7]
            if (got > 0) { //[cite: 7]
                pending.append(ioBuf.data(), static_cast<size_t>(got)); //[cite: 7]
            }
            if (got <= 0 || static_cast<size_t>(got) < ioBuf.size()) { //[cite: 7]
                eof = true; //[cite: 7]
            }
            continue; //[cite: 7]
        }

        available = pending.size() - consumedPos; //[cite: 7]
        if (available == 0) break; //[cite: 7]

        size_t len = std::min(blockSize, available); //[cite: 7]
        const uint8_t* blockPtr =
            reinterpret_cast<const uint8_t*>(pending.data() + consumedPos); //[cite: 7]
        double h = EntropyCalculator::calculate(blockPtr, len); //[cite: 7]

        if (h >= config_.entropyThreshold) { //[cite: 7]
            flushTextSegment(); //[cite: 7]
            if (!inEntropyRegion) { //[cite: 7]
                inEntropyRegion = true; //[cite: 7]
                entropyRegionStart = fileOffset; //[cite: 7]
                entropyRegionMax = h; //[cite: 7]
            } else {
                entropyRegionMax = std::max(entropyRegionMax, h); //[cite: 7]
            }
            entropyRegionLen += len; //[cite: 7]
        } else {
            flushEntropyRegion(); //[cite: 7]
            if (!inTextSegment) { //[cite: 7]
                inTextSegment = true; //[cite: 7]
                textSegmentStart = fileOffset; //[cite: 7]
            }
            textSegment.append(reinterpret_cast<const char*>(blockPtr), len); //[cite: 7]

            if (textSegment.size() >= maxSegmentSize) { //[cite: 7]
                auto found = engine.scan(textSegment, textSegmentStart, path); //[cite: 7]
                for (auto& f : found) {
                    if (config_.enableAi && !f.rawValue.empty()) {
                        f.aiVerdict = AiAnalyzer::analyzeContext(f.rawValue, toString(f.type));
                    }
                    findings.push_back(std::move(f)); //[cite: 7]
                }

                if (textSegment.size() > keepOverlap) { //[cite: 7]
                    std::string tail = textSegment.substr(textSegment.size() - keepOverlap); //[cite: 7]
                    textSegmentStart = fileOffset + len - tail.size(); //[cite: 7]
                    textSegment = std::move(tail); //[cite: 7]
                } else {
                    textSegment.clear(); //[cite: 7]
                    textSegmentStart = fileOffset + len; //[cite: 7]
                }
            }
        }

        consumedPos += len; //[cite: 7]
        fileOffset += len; //[cite: 7]
    }

    flushTextSegment(); //[cite: 7]
    flushEntropyRegion(); //[cite: 7]

    return findings; //[cite: 7]
}

std::vector<Finding> Scanner::run() const { //[cite: 7]
    std::vector<std::string> files = collectFiles(); //[cite: 7]

    unsigned threadCount = config_.threadCount; //[cite: 7]
    if (threadCount == 0) { //[cite: 7]
        threadCount = std::thread::hardware_concurrency(); //[cite: 7]
        if (threadCount == 0) threadCount = 2; //[cite: 7]
    }
    threadCount = static_cast<unsigned>(
        std::min<size_t>(threadCount, std::max<size_t>(1, files.size()))); //[cite: 7]

    std::vector<std::vector<Finding>> perThread(threadCount); //[cite: 7]
    std::atomic<size_t> nextIndex{0}; //[cite: 7]
    std::vector<std::thread> workers; //[cite: 7]
    workers.reserve(threadCount); //[cite: 7]

    for (unsigned t = 0; t < threadCount; ++t) { //[cite: 7]
        workers.emplace_back([this, &files, &perThread, &nextIndex, t]() {
            while (true) { //[cite: 7]
                size_t idx = nextIndex.fetch_add(1); //[cite: 7]
                if (idx >= files.size()) break; //[cite: 7]
                auto fileFindings = scanFile(files[idx]); //[cite: 7]
                auto& bucket = perThread[t]; //[cite: 7]
                bucket.insert(bucket.end(),
                               std::make_move_iterator(fileFindings.begin()),
                               std::make_move_iterator(fileFindings.end())); //[cite: 7]
            }
        });
    }

    for (auto& w : workers) w.join(); //[cite: 7]

    std::vector<Finding> all; //[cite: 7]
    for (auto& bucket : perThread) { //[cite: 7]
        all.insert(all.end(),
                   std::make_move_iterator(bucket.begin()),
                   std::make_move_iterator(bucket.end())); //[cite: 7]
    }
    return all; //[cite: 7]
}

} // namespace dlp