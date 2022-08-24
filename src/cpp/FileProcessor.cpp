#include <stdexcept>
#include <random>
#include <fstream>
#include "../header/FileProcessor.h"

FileProcessor::FileProcessor(std::string source, std::string dest): src(std::move(source)), dst(std::move(dest)) {
}

std::vector<uint8_t> FileProcessor::readChunk(std::ifstream& file, int byteCnt) {
    char out[byteCnt];
    file.read(out, byteCnt);
    size_t n = file.gcount();
    std::vector<uint8_t> result;
    result.reserve(byteCnt);
    for(size_t i = 0; i < n; i++){
        result.push_back(out[i]);
    }
    return result;
}

void FileProcessor::process(const std::function<void(std::ifstream &, std::ofstream &)> &callBack) {
    std::ifstream inputFile(src, std::ios_base::binary | std::ios_base::in );
    std::ofstream outputFile(dst, std::ios_base::binary | std::ios_base::out);
    callBack(inputFile, outputFile);
}