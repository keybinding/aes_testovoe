#ifndef TESTOVOE_ZADANIE_AES256BLOCKPROCESSOR_H
#define TESTOVOE_ZADANIE_AES256BLOCKPROCESSOR_H


#include "AesBlockProcessor.h"

class Aes256BlockProcessor : AesBlockProcessor {
public:
    const int Nb = 4;
    const int Nr = 14;
    ~Aes256BlockProcessor() override = default;
    std::vector<uint8_t> encryptBlock(std::vector<uint8_t>& block, std::vector<uint8_t> &keySchedule) override;
    std::vector<uint8_t> decryptBlock(std::vector<uint8_t>& block, std::vector<uint8_t> &keySchedule) override;

private:
    void addRoundKey(std::vector<std::vector<uint8_t>> &state, std::vector<uint8_t> &expandedKey, size_t startFrom);

    void subBytes(std::vector<std::vector<uint8_t>> &state);

    void shiftRows(std::vector<std::vector<uint8_t>> &state);

    void mixColumns(std::vector<std::vector<uint8_t>> &state);

    void shiftRow(std::vector<std::vector<uint8_t>> &state, int rowIdx, int n);

    void invSubBytes(std::vector<std::vector<uint8_t>> &state);

    void invShiftRows(std::vector<std::vector<uint8_t>> &state);

    void invMixColumns(std::vector<std::vector<uint8_t>> &state);
};


#endif //TESTOVOE_ZADANIE_AES256BLOCKPROCESSOR_H
