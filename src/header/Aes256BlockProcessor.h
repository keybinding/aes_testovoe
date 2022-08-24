//
// Created by Romanv Denis on 24.08.2022.
//

#ifndef TESTOVOE_ZADANIE_AES256BLOCKPROCESSOR_H
#define TESTOVOE_ZADANIE_AES256BLOCKPROCESSOR_H


#include "AesBlockProcessor.h"

class Aes256BlockProcessor : AesBlockProcessor {
public:
    static const int Nk = 8;
    static const int Nb = 4;
    static const int Nr = 14;
    ~Aes256BlockProcessor() override = default;
    std::vector<uint8_t> encryptBlock(std::vector<uint8_t>& block, std::vector<uint8_t> &keySchedule) override;
    std::vector<uint8_t> decryptBlock(std::vector<uint8_t>& block, std::vector<uint8_t> &keySchedule) override;

private:
    static void addRoundKey(std::vector<std::vector<uint8_t>> &state, std::vector<uint8_t> &expandedKey, size_t startFrom);

    static void subBytes(std::vector<std::vector<uint8_t>> &state);

    static void shiftRows(std::vector<std::vector<uint8_t>> &state);

    static void mixColumns(std::vector<std::vector<uint8_t>> &state);

    static void shiftRow(std::vector<std::vector<uint8_t>> &state, int rowIdx, int n);

    static void invSubBytes(std::vector<std::vector<uint8_t>> &state);

    static void invShiftRows(std::vector<std::vector<uint8_t>> &state);

    static void invMixColumns(std::vector<std::vector<uint8_t>> &state);
};


#endif //TESTOVOE_ZADANIE_AES256BLOCKPROCESSOR_H
