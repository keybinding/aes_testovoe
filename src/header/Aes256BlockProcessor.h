#ifndef TESTOVOE_ZADANIE_AES256BLOCKPROCESSOR_H
#define TESTOVOE_ZADANIE_AES256BLOCKPROCESSOR_H


#include "AesBlockProcessor.h"

class Aes256BlockProcessor : AesBlockProcessor {
public:
    /**
     * Number of columns in state
     */
    const int Nb = 4;
    /**
     * Number of rounds
     */
    const int Nr = 14;
    ~Aes256BlockProcessor() override = default;
    /**
     * Encrypts block
     * @param block block to encrypt 16 byte
     * @param keySchedule rounds key schedule
     * @return encrypted block
     */
    std::vector<uint8_t> encryptBlock(std::vector<uint8_t>& block, std::vector<uint8_t> &keySchedule) override;
    /**
     * Decrypts block
     * @param block block to decrypt 16 byte
     * @param keySchedule rounds key schedule
     * @return encrypted block
     */
    std::vector<uint8_t> decryptBlock(std::vector<uint8_t>& block, std::vector<uint8_t> &keySchedule) override;

private:

    /**
     * addRoundKey step
     * @param state
     * @param keySchedule rounds key schedule
     * @param startFrom Index in keySchedule
     */
    void addRoundKey(std::vector<std::vector<uint8_t>> &state, std::vector<uint8_t> &keySchedule, size_t startFrom);

    /**
     * Left rotation of row in state
     * @param state
     * @param rowIdx Row index
     * @param n rotate factor
     */
    void shiftRow(std::vector<std::vector<uint8_t>> &state, int rowIdx, int n);

    void subBytes(std::vector<std::vector<uint8_t>> &state);

    void shiftRows(std::vector<std::vector<uint8_t>> &state);

    void mixColumns(std::vector<std::vector<uint8_t>> &state);

    void invSubBytes(std::vector<std::vector<uint8_t>> &state);

    void invShiftRows(std::vector<std::vector<uint8_t>> &state);

    void invMixColumns(std::vector<std::vector<uint8_t>> &state);
};


#endif //TESTOVOE_ZADANIE_AES256BLOCKPROCESSOR_H
