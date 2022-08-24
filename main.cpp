#include <iostream>
#include <utility>
#include <fstream>
#include <vector>
#include <random>
#include "include/SHA256.h"
#include "src/header/aes_consts.h"
#include "src/header/Aes256KeyExpander.h"
#include "src/header/Aes256BlockProcessor.h"

#define CHUNK_SIZE 1024
#define BLOCK_SIZE 16

enum Mode {ENCRYPT, DECRYPT};

class CtrModeProcessor {

};

class FileProcessor {
public:
    FileProcessor(std::string source, std::string dest, Mode mode, std::string password);
    void process();
private:
    const std::string src;
    const std::string dst;
    const std::string pwd;
    const Mode mode;

    static std::vector<uint8_t> readChunk(std::ifstream &file, int byteCnt);

    std::vector<uint8_t> passwordSha256(std::string const&basicString);

    static std::vector<uint8_t> getRandomNonce();

    static std::vector<uint8_t> readNonce(std::ifstream& source);

    static void saveNonce(std::vector<uint8_t>& nonce, std::ofstream& out);

    static std::vector<uint8_t> makeCtrBlock(std::vector<uint8_t> &nonce, uint32_t counter);
};



FileProcessor::FileProcessor(std::string source, std::string dest, Mode mode, std::string password): src(std::move(source)), dst(std::move(dest)), mode(mode), pwd(std::move(password)) {
}

Mode getMode(const char *mode);

void FileProcessor::process() {
    std::ifstream file(src, std::ios_base::binary | std::ios_base::in );
    std::ofstream outFile(dst, std::ios_base::binary | std::ios_base::out);
    auto nonce = mode == ENCRYPT ? getRandomNonce() : readNonce(file);
    if (mode == ENCRYPT)
        saveNonce(nonce, outFile);
    auto key = passwordSha256(pwd);
    Aes256KeyExpander keyExpander;
    Aes256BlockProcessor blockProcessor;
    std::vector<uint8_t> expandedKey = keyExpander.keyExpansion(key);
    while(!file.eof()) {
        uint32_t blocksCounter = 1;
        std::vector<uint8_t> chunk = readChunk(file, CHUNK_SIZE);
        std::vector<uint8_t> out(chunk.size(), 0);
        size_t blocks = chunk.size() / BLOCK_SIZE;
        for (int i = 0; i < blocks; i++) {
            std::vector<uint8_t> counterBlock = makeCtrBlock(nonce, blocksCounter);
            std::vector<uint8_t> block = blockProcessor.encryptBlock(counterBlock, expandedKey);
            for (int j = 0; j < BLOCK_SIZE; ++j)
                out[i * BLOCK_SIZE + j] = block[j] ^ chunk[i * BLOCK_SIZE + j];
            blocksCounter++;
        }
        int bytesLeft = chunk.size() % BLOCK_SIZE;
        if (bytesLeft != 0) {
            std::vector<uint8_t> counterBlock = makeCtrBlock(nonce, blocksCounter);
            std::vector<uint8_t> block = blockProcessor.encryptBlock(counterBlock, expandedKey);
            for (int j = 0; j < bytesLeft; ++j)
                out[blocks * BLOCK_SIZE + j] = block[j] ^ chunk[blocks * BLOCK_SIZE + j];
        }
        outFile.write((const char*)out.data(), out.size());
    }
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

std::vector<uint8_t> FileProcessor::passwordSha256(std::string const&basicString) {
    SHA256 sha;
    sha.update(pwd);
    uint8_t* pwdHash = sha.digest();
    std::vector<uint8_t> result(256, 0);
    for(size_t i = 0; i < result.size(); i++){
        result[i] = pwdHash[i];
    }
    delete[] pwdHash;
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

std::vector<uint8_t> FileProcessor::makeCtrBlock(std::vector<uint8_t> &nonce, uint32_t counter) {
    std::vector<uint8_t> ctrBlock = std::vector<uint8_t>(BLOCK_SIZE, 0);
    if (nonce.size() != BLOCK_SIZE)
        throw std::invalid_argument("Nonce length must be 16 byte");
    std::copy(nonce.begin(), nonce.end(), ctrBlock.begin());
    for(int i = 0; i < 4; i++){
        counter = counter >> (i * 8);
        ctrBlock[i] = counter & 0xff;
    }
    return ctrBlock;
}

int main(int argc, char *argv[]) {
    Mode mode = getMode(argv[4]);
    std::string pwd(argv[3]);
    FileProcessor encrypt(argv[1], argv[2], mode, argv[3]);
    encrypt.process();
    return 0;
}

Mode getMode(const char *mode) {
    if (*mode == 'e')
        return ENCRYPT;
    if (*mode == 'd')
        return DECRYPT;
    throw std::invalid_argument("Wrong mode. e/d expected.");
}
