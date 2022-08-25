#include <iostream>
#include <fstream>
#include "src/header/Aes256Ctr.h"
#include "src/header/FileProcessor.h"
#include "src/header/AppProperties.h"

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
            auto chunk = FileProcessor::readChunk(source, properties->inputSize);
            auto out = properties->mode == ENCRYPT ? aes256Ctr.encrypt(chunk) : aes256Ctr.decrypt(chunk);
            dest.write((const char*)out.data(), out.size());
        }
    });
    return 0;
}
