#include <random>
#include "../header/Aes256Ctr.h"
#include "../header/Aes256KeyExpander.h"
#include "../header/Aes256BlockProcessor.h"
#include "SHA256.h"
#include "../header/FileProcessor.h"
#include <omp.h>
#include <thread>

std::vector<uint8_t> Aes256Ctr::encrypt(std::vector<uint8_t> &in) {
    Aes256KeyExpander keyExpander;
    Aes256BlockProcessor blockProcessor;
    auto key = passwordSha256();
    auto expandedKey = keyExpander.keyExpansion(key);
    blockCounter++;
    std::vector<uint8_t> out(in.size(), 0);
    size_t blocks = in.size() / blockSize;
    #pragma omp parallel for shared(blockCounter, out)
        for (size_t i = 0; i < blocks; i++) {
            auto counterBlock = makeCtrBlock(blockCounter + i);
            auto block = blockProcessor.encryptBlock(counterBlock, expandedKey);
            for (int j = 0; j < blockSize; ++j)
                out[i * blockSize + j] = block[j] ^ in[i * blockSize + j];
        }

    blockCounter+=blocks;
    size_t bytesLeft = in.size() % blockSize;
    if (bytesLeft != 0) {
        auto counterBlock = makeCtrBlock(blockCounter);
        auto block = blockProcessor.encryptBlock(counterBlock, expandedKey);
        for (int j = 0; j < bytesLeft; ++j)
            out[blocks * blockSize + j] = block[j] ^ in[blocks * blockSize + j];
    }
    return out;
}

std::vector<uint8_t> Aes256Ctr::decrypt(std::vector<uint8_t> &in) {
    return encrypt(in);
}

std::vector<uint8_t> Aes256Ctr::passwordSha256() {
    SHA256 sha;
    sha.update(password);
    uint8_t* pwdHash = sha.digest();
    std::vector<uint8_t> result(256, 0);
    for(size_t i = 0; i < result.size(); i++){
        result[i] = pwdHash[i];
    }
    delete[] pwdHash;
    return result;
}

std::vector<uint8_t> Aes256Ctr::makeCtrBlock(uint32_t counter) {
    std::vector<uint8_t> ctrBlock = std::vector<uint8_t>(blockSize, 0);
    if (nonce.size() != blockSize)
        throw std::invalid_argument("Nonce length must be 16 byte");
    std::copy(nonce.begin(), nonce.end(), ctrBlock.begin());
    for(int i = 0; i < 4; i++){
        counter = counter >> (i * 8);
        ctrBlock[i] = counter & 0xff;
    }
    return ctrBlock;
}

std::vector<uint8_t> Aes256Ctr::getRandomNonce() {
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0,255);
    std::vector<uint8_t> nonce(16, 0);
    for (uint8_t& d : nonce)
    {
        d = static_cast<uint8_t>(dist(rd) & 0xFF);
    }
    return nonce;
}

std::vector<uint8_t> Aes256Ctr::readNonce(std::ifstream& source) {
    auto nonce = FileProcessor::readChunk(source, 16);
    if (nonce.size() != 16)
        throw std::invalid_argument("Couldn't read first 16 bytes of nonce from provided source.");
    return nonce;
}