#include "../header/Aes256BlockProcessor.h"
#include "../header/aes_consts.h"

std::vector<uint8_t> Aes256BlockProcessor::encryptBlock(std::vector<uint8_t>& block, std::vector<uint8_t> &keySchedule) {
    std::vector<uint8_t> out(4 * Nb, 0);
    std::vector<std::vector<uint8_t>> state = {
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
    };
    for(size_t i = 0; i < state.size(); i++)
        for(size_t j = 0; j < state[1].size(); j++)
            state[i][j] = block[i + 4 * j];

    addRoundKey(state, keySchedule, 0);

    for (int round = 1; round <= Nr - 1; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, keySchedule, round * 4 * Nb);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, keySchedule, Nr * 4 * Nb);

    for(int i = 0; i < state.size(); i++)
        for(int j = 0; j < state[i].size(); j++)
            out[i + 4 * j] = state[i][j];

    return out;
}

std::vector<uint8_t> Aes256BlockProcessor::decryptBlock(std::vector<uint8_t>& block, std::vector<uint8_t> &keySchedule) {
    std::vector<uint8_t> out(4 * Nb, 0);
    std::vector<std::vector<uint8_t>> state = {
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
    };
    for(size_t i = 0; i < state.size(); i++)
        for(size_t j = 0; j < state[1].size(); j++)
            state[i][j] = block[i + 4 * j];
    addRoundKey(state, keySchedule, Nr * 4 * Nb);
    for (int round = Nr - 1; round >= 1; round--) {
        invSubBytes(state);
        invShiftRows(state);
        addRoundKey(state, keySchedule, round * 4 * Nb);
        invMixColumns(state);
    }

    invSubBytes(state);
    invShiftRows(state);
    addRoundKey(state, keySchedule, 0);

    for(int i = 0; i < state.size(); i++)
        for(int j = 0; j < state[i].size(); j++)
            out[i + 4 * j] = state[i][j];

    return out;
}

void Aes256BlockProcessor::addRoundKey(std::vector<std::vector<uint8_t>> &state, std::vector<uint8_t> &expandedKey,
                                       size_t startFrom) {
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = state[i][j] ^ expandedKey[startFrom + i + 4 * j];
        }
    }
}

void Aes256BlockProcessor::subBytes(std::vector<std::vector<uint8_t>> &state) {
    uint8_t t;
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = AesConsts::SBOX[t / 16][t % 16];
        }
    }
}

void Aes256BlockProcessor::shiftRows(std::vector<std::vector<uint8_t>> &state) {
    shiftRow(state, 1, 1);
    shiftRow(state, 2, 2);
    shiftRow(state, 3, 3);
}

void Aes256BlockProcessor::mixColumns(std::vector<std::vector<uint8_t>> &state) {
    std::vector<std::vector<uint8_t>> tmp_state = {
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
    };

    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                if (AesConsts::CMDS[i][k] == 1)
                    tmp_state[i][j] ^= state[k][j];
                else
                    tmp_state[i][j] ^= AesConsts::GF_MUL_TABLE[AesConsts::CMDS[i][k]][state[k][j]];
            }
        }
    }
    for(size_t i = 0; i < state.size(); i++)
        state[i] = std::move(tmp_state[i]);
}

void Aes256BlockProcessor::shiftRow(std::vector<std::vector<uint8_t>> &state, int rowIdx, int n) {
    std::vector<uint8_t> tmp = std::move(state[rowIdx]);
    std::rotate(tmp.begin(), tmp.begin() + n, tmp.end());
    state[rowIdx] = std::move(tmp);
}

void Aes256BlockProcessor::invSubBytes(std::vector<std::vector<uint8_t>> &state) {
    uint8_t t;
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = AesConsts::INV_SBOX[t / 16][t % 16];
        }
    }
}

void Aes256BlockProcessor::invShiftRows(std::vector<std::vector<uint8_t>> &state) {
    shiftRow(state, 1, 3);
    shiftRow(state, 2, 2);
    shiftRow(state, 3, 1);
}

void Aes256BlockProcessor::invMixColumns(std::vector<std::vector<uint8_t>> &state) {
    std::vector<std::vector<uint8_t>> tmp_state = {
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
    };

    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                tmp_state[i][j] ^= AesConsts::GF_MUL_TABLE[AesConsts::INV_CMDS[i][k]][state[k][j]];
            }
        }
    }

    for(size_t i = 0; i < state.size(); i++)
        state[i] = std::move(tmp_state[i]);
}
