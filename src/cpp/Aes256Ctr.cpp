#include "../header/Aes256Ctr.h"
#include "../header/Aes256KeyExpander.h"
#include "../header/Aes256BlockProcessor.h"
#include "SHA256.h"

std::vector<uint8_t> Aes256Ctr::encrypt(std::vector<uint8_t> &in) {
    Aes256KeyExpander keyExpander;
    Aes256BlockProcessor blockProcessor;
    auto key = passwordSha256();
    auto expandedKey = keyExpander.keyExpansion(key);
    blockCounter++;
    std::vector<uint8_t> out(in.size(), 0);
    size_t blocks = in.size() / blockSize;
    for (int i = 0; i < blocks; i++) {
        std::vector<uint8_t> counterBlock = makeCtrBlock(blockCounter);
        std::vector<uint8_t> block = blockProcessor.encryptBlock(counterBlock, expandedKey);
        for (int j = 0; j < blockSize; ++j)
            out[i * blockSize + j] = block[j] ^ in[i * blockSize + j];
        blockCounter++;
    }
    int bytesLeft = in.size() % blockSize;
    if (bytesLeft != 0) {
        std::vector<uint8_t> counterBlock = makeCtrBlock(blockCounter);
        std::vector<uint8_t> block = blockProcessor.encryptBlock(counterBlock, expandedKey);
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
