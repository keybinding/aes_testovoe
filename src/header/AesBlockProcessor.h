//
// Created by Romanv Denis on 24.08.2022.
//

#ifndef TESTOVOE_ZADANIE_AESBLOCKPROCESSOR_H
#define TESTOVOE_ZADANIE_AESBLOCKPROCESSOR_H

#include <cstdint>
#include <vector>

class AesBlockProcessor {
public:
    virtual std::vector<uint8_t> encryptBlock(std::vector<uint8_t>& block, std::vector<uint8_t> &keySchedule) = 0;
    virtual std::vector<uint8_t> decryptBlock(std::vector<uint8_t>& block, std::vector<uint8_t> &keySchedule) = 0;
    virtual ~AesBlockProcessor() = default;
};
#endif //TESTOVOE_ZADANIE_AESBLOCKPROCESSOR_H
