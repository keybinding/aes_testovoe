#include <iostream>
#include <fstream>
#include "src/header/Aes256KeyExpander.h"
#include "src/header/Aes256Ctr.h"
#include "src/header/FileProcessor.h"
#include "src/header/AppProperties.h"

#define CHUNK_SIZE 1073741824 //8196

Mode getMode(const char *mode) {
    if (*mode == 'e')
        return ENCRYPT;
    if (*mode == 'd')
        return DECRYPT;
    throw std::invalid_argument("Wrong mode. e/d expected.");
}

int main(int argc, char *argv[]) {
    auto properties = AppProperties::build(argc, argv);
    FileProcessor fileProcessor(argv[1], argv[2]);
    fileProcessor.process([properties](std::ifstream &source, std::ofstream &dest){
        auto nonce = properties->mode == ENCRYPT ? Aes256Ctr::getRandomNonce() : Aes256Ctr::readNonce(source);
        if (properties->mode == ENCRYPT)
            //save nonce in first block
            dest.write((const char*)nonce.data(), nonce.size());
        Aes256Ctr aes256Ctr(properties->password, nonce);
        while(!source.eof()) {
            auto chunk = FileProcessor::readChunk(source, CHUNK_SIZE);
            auto out = properties->mode == ENCRYPT ? aes256Ctr.encrypt(chunk) : aes256Ctr.decrypt(chunk);
            dest.write((const char*)out.data(), out.size());
        }
    });
    return 0;
}
