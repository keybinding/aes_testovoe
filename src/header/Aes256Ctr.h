#ifndef TESTOVOE_ZADANIE_AES256CTR_H
#define TESTOVOE_ZADANIE_AES256CTR_H


#include <utility>
#include <vector>
#include <cstdint>
#include <string>

class Aes256Ctr {
public:
    static const int blockSize = 16;
    explicit Aes256Ctr(std::string password, std::vector<uint8_t> nonce): password(std::move(password)), blockCounter(0), nonce(std::move(nonce)){}
    std::vector<uint8_t> encrypt(std::vector<uint8_t>& in);
    std::vector<uint8_t> decrypt(std::vector<uint8_t>& in);
private:
    const std::string password;
    uint32_t blockCounter;
    std::vector<uint8_t> nonce;

    std::vector<uint8_t> passwordSha256();
    std::vector<uint8_t> makeCtrBlock(uint32_t counter);
};


#endif //TESTOVOE_ZADANIE_AES256CTR_H
