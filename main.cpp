#include <iostream>
#include <utility>
#include <fstream>
#include <vector>
#include <random>
#include <functional>
#include "include/SHA256.h"
#include "src/header/aes_consts.h"
#include "src/header/Aes256KeyExpander.h"
#include "src/header/Aes256Ctr.h"

#define CHUNK_SIZE 1024
#define BLOCK_SIZE 16

enum Mode {ENCRYPT, DECRYPT};

class FileProcessor {
public:
    FileProcessor(std::string source, std::string dest);
    void process(const std::function <void (std::ifstream&, std::ofstream&)>& callBack);

    static std::vector<uint8_t> getRandomNonce();
    static std::vector<uint8_t> readNonce(std::ifstream& source);
    static void saveNonce(std::vector<uint8_t>& nonce, std::ofstream& out);
    static std::vector<uint8_t> readChunk(std::ifstream &file, int byteCnt);
private:
    const std::string src;
    const std::string dst;
};



FileProcessor::FileProcessor(std::string source, std::string dest): src(std::move(source)), dst(std::move(dest)) {
}

Mode getMode(const char *mode);

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

std::vector<uint8_t> FileProcessor::getRandomNonce() {
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0,255);
    std::vector<uint8_t> nonce(16, 0);
    for (uint8_t& d : nonce)
    {
        d = static_cast<uint8_t>(dist(rd) & 0xFF);
    }
    return nonce;
}

std::vector<uint8_t> FileProcessor::readNonce(std::ifstream& source) {
    auto nonce = readChunk(source, BLOCK_SIZE);
    if (nonce.size() != BLOCK_SIZE)
        throw std::invalid_argument("Не удалось прочитать nonce");
    return nonce;
}

void FileProcessor::saveNonce(std::vector<uint8_t>& nonce, std::ofstream& out) {
    out.write((const char*)nonce.data(), nonce.size());
}

void FileProcessor::process(const std::function<void(std::ifstream &, std::ofstream &)> &callBack) {
    std::ifstream inputFile(src, std::ios_base::binary | std::ios_base::in );
    std::ofstream outputFile(dst, std::ios_base::binary | std::ios_base::out);
    callBack(inputFile, outputFile);
}

int main(int argc, char *argv[]) {
    Mode mode = getMode(argv[4]);
    std::string pwd(argv[3]);
    FileProcessor fileProcessor(argv[1], argv[2]);
    fileProcessor.process([&mode, &pwd](std::ifstream &source, std::ofstream &dest){
        auto nonce = mode == ENCRYPT ? FileProcessor::getRandomNonce() : FileProcessor::readNonce(source);
        if (mode == ENCRYPT)
            FileProcessor::saveNonce(nonce, dest);
        Aes256Ctr aes256Ctr(pwd, nonce);
        while(!source.eof()) {
            auto chunk = FileProcessor::readChunk(source, CHUNK_SIZE);
            auto out = aes256Ctr.encrypt(chunk);
            dest.write((const char*)out.data(), out.size());
        }
    });
    return 0;
}

Mode getMode(const char *mode) {
    if (*mode == 'e')
        return ENCRYPT;
    if (*mode == 'd')
        return DECRYPT;
    throw std::invalid_argument("Wrong mode. e/d expected.");
}
