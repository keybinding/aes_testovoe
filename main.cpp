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
#include "src/header/FileProcessor.h"

#define CHUNK_SIZE 1024
#define BLOCK_SIZE 16

enum Mode {ENCRYPT, DECRYPT};

Mode getMode(const char *mode) {
    if (*mode == 'e')
        return ENCRYPT;
    if (*mode == 'd')
        return DECRYPT;
    throw std::invalid_argument("Wrong mode. e/d expected.");
}

int main(int argc, char *argv[]) {
    Mode mode = getMode(argv[4]);
    std::string pwd(argv[3]);
    FileProcessor fileProcessor(argv[1], argv[2]);
    fileProcessor.process([&mode, &pwd](std::ifstream &source, std::ofstream &dest){
        auto nonce = mode == ENCRYPT ? Aes256Ctr::getRandomNonce() : Aes256Ctr::readNonce(source);
        if (mode == ENCRYPT)
            //save nonce in first block
            dest.write((const char*)nonce.data(), nonce.size());
        Aes256Ctr aes256Ctr(pwd, nonce);
        while(!source.eof()) {
            auto chunk = FileProcessor::readChunk(source, CHUNK_SIZE);
            auto out = aes256Ctr.encrypt(chunk);
            dest.write((const char*)out.data(), out.size());
        }
    });
    return 0;
}
