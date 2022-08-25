#include <stdexcept>
#include <fstream>
#include "../header/FileProcessor.h"

FileProcessor::FileProcessor(std::string source, std::string dest): src(std::move(source)), dst(std::move(dest)) {
}

std::vector<uint8_t> FileProcessor::readChunk(std::ifstream& file, uint32_t byteCnt) {
    std::vector<uint8_t> result(byteCnt, 0);
    file.read(reinterpret_cast<std::ifstream::char_type*>(&result.front()), byteCnt);
    auto actuallyRead = file.gcount();
    if (actuallyRead != byteCnt)
        result.erase(result.begin() + actuallyRead, result.end());;
    return result;
}

void FileProcessor::process(const std::function<void(std::ifstream &, std::ofstream &)> &callBack) {
    std::ifstream inputFile(src, std::ios_base::binary | std::ios_base::in);
    std::ofstream outputFile(dst, std::ios_base::binary | std::ios_base::out);
    callBack(inputFile, outputFile);
}