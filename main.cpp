#include <iostream>
#include <utility>
#include <fstream>
#include <vector>
#include <random>
#include "include/SHA256.h"
#include "include/aes_consts.h"

#define CHUNK_SIZE 128
#define BLOCK_SIZE 16

enum Mode {ENCRYPT, DECRYPT};

class FileProcessor {
public:
    FileProcessor(std::string source, std::string dest, Mode mode, std::string password);
    void process();
private:
    const std::string src;
    const std::string dst;
    const std::string pwd;
    const Mode mode;
    static const int Nk = 8;
    static const int Nb = 4;
    static const int Nr = 14;

    static std::vector<uint8_t> encryptBlock(std::vector<uint8_t> &in, std::vector<uint8_t> &key, size_t startFrom);
    static std::vector<uint8_t> decryptBlock(std::vector<uint8_t> &in, std::vector<uint8_t> &key, size_t startFrom);
    static std::vector<uint8_t> readChunk(std::ifstream &file);
    static std::vector<uint8_t> keyExpansion(std::vector<uint8_t>& key);

    std::vector<uint8_t> passwordSha256(std::string const&basicString);

    static void rotWord(uint8_t word[4]);

    static void subWord(uint8_t word[4]);

    static void addRoundKey(std::vector<std::vector<uint8_t>> &state, std::vector<uint8_t> &expandedKey, size_t startFrom);

    static void subBytes(std::vector<std::vector<uint8_t>> &state);

    static void shiftRows(std::vector<std::vector<uint8_t>> &state);

    static void mixColumns(std::vector<std::vector<uint8_t>> &state);

    static void shiftRow(std::vector<std::vector<uint8_t>> &state, int rowIdx, int n);

    static void invSubBytes(std::vector<std::vector<uint8_t>> &state);

    static void invShiftRows(std::vector<std::vector<uint8_t>> &state);

    static void invMixColumns(std::vector<std::vector<uint8_t>> &state);

    static void debugState(std::vector<std::vector<uint8_t>> &state);

    std::vector<uint8_t> getRandomNonce();

    std::vector<uint8_t> readNonce();
};



FileProcessor::FileProcessor(std::string source, std::string dest, Mode mode, std::string password): src(std::move(source)), dst(std::move(dest)), mode(mode), pwd(std::move(password)) {
}

Mode getMode(const char *mode);

void FileProcessor::process() {
    std::vector<uint8_t> pwdHash = passwordSha256(pwd);
    std::vector<uint8_t> nonce = mode == ENCRYPT ? getRandomNonce() : readNonce();

    std::ifstream file(src);
    std::ofstream outFile(dst);
    while(!file.eof()) {
        std::vector<uint8_t> chunk = readChunk(file);
        std::vector<uint8_t> expandedKey = keyExpansion(pwdHash);
        std::vector<uint8_t> out(chunk.size(), 0);
        size_t blocks = chunk.size() / BLOCK_SIZE;
        for (int i = 0; i < blocks; i++) {
            std::vector<uint8_t> block;
            switch (mode) {
                case ENCRYPT:
                    block = encryptBlock(chunk, expandedKey, i * BLOCK_SIZE);
                    break;
                case DECRYPT:
                    block = decryptBlock(chunk, expandedKey, i * BLOCK_SIZE);
                    break;
            }
            std::copy(block.begin(), block.end(), out.begin() + i * BLOCK_SIZE);
        }
        if (chunk.size() % BLOCK_SIZE != 0)
            std::copy(chunk.begin() + blocks * BLOCK_SIZE, chunk.end(), out.begin() + blocks * BLOCK_SIZE);

        outFile.write((const char*)out.data(), out.size());
    }
}

std::vector<uint8_t>
FileProcessor::encryptBlock(std::vector<uint8_t> &in, std::vector<uint8_t> &expandedKey, size_t startFrom) {
    std::vector<uint8_t> out(4 * Nb, 0);
    std::vector<std::vector<uint8_t>> state = {
        std::vector<uint8_t>(4, 0),
        std::vector<uint8_t>(4, 0),
        std::vector<uint8_t>(4, 0),
        std::vector<uint8_t>(4, 0),
    };
    for(size_t i = 0; i < state.size(); i++)
        for(size_t j = 0; j < state[1].size(); j++)
            state[i][j] = in[startFrom + i + 4 * j];

    addRoundKey(state, expandedKey, 0);

    for (int round = 1; round <= Nr - 1; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expandedKey, round * 4 * Nb);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expandedKey, Nr * 4 * Nb);

    for(int i = 0; i < state.size(); i++)
        for(int j = 0; j < state[i].size(); j++)
            out[i + 4 * j] = state[i][j];

    return out;
}

std::vector<uint8_t> FileProcessor::readChunk(std::ifstream& file) {
    char out[CHUNK_SIZE];
    file.read(out, CHUNK_SIZE);
    size_t n = file.gcount();
    std::vector<uint8_t> result;
    result.reserve(CHUNK_SIZE);
    for(size_t i = 0; i < n; i++){
        result.push_back(out[i]);
    }
    return result;
}

std::vector<uint8_t> FileProcessor::keyExpansion(std::vector<uint8_t> &key) {
    uint8_t temp[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t rcon[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t ci[10] = {0x01, 0x02, 0x04, 0x08, 0x10,0x20, 0x40, 0x80, 0x1b, 0x36};
    std::vector<uint8_t> expandedKey(4 * (Nr + 1) * 4, 0);
    for(size_t i = 0; i < 4 * (Nr + 1); i++) {
        size_t beg = 4 * i;
        if (i < Nk) {
            for(size_t j = beg; j < beg + 4; j++)
                expandedKey[j] = key[j];
        }
        else if (i % Nk == 0) {
            for(size_t im1 = beg - 4, k = 0; im1 < beg; im1++, k++)
                temp[k] = expandedKey[im1];
            rotWord(temp);
            subWord(temp);
            rcon[0] = ci[i / Nk - 1];
            for(size_t j = beg, k = 0; j < beg + 4; j++, k++)
                expandedKey[j] = expandedKey[j - Nk * 4] ^ temp[k] ^ rcon[k];
        }
        else if (i % Nk == 4){
            for(size_t im1 = beg - 4, k = 0; im1 < beg; im1++, k++)
                temp[k] = expandedKey[im1];
            subWord(temp);
            for(size_t j = beg, k = 0; j < beg + 4; j++, k++)
                expandedKey[j] = expandedKey[j - Nk * 4] ^ temp[k];
        }
        else {
            for(size_t im1 = beg - 4, k = 0; im1 < beg; im1++, k++)
                temp[k] = expandedKey[im1];
            for(size_t j = beg, k = 0; j < beg + 4; j++, k++)
                expandedKey[j] = expandedKey[j - Nk * 4] ^ temp[k];
        }
    }
    return expandedKey;
}

std::vector<uint8_t> FileProcessor::passwordSha256(std::string const&basicString) {
    SHA256 sha;
    sha.update(pwd);
    uint8_t* pwdHash = sha.digest();
    std::vector<uint8_t> result(256, 0);
    for(size_t i = 0; i < result.size(); i++){
        result[i] = pwdHash[i];
    }
    delete[] pwdHash;
    return result;
}

void FileProcessor::rotWord(uint8_t *word) {
    uint8_t c = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = c;
}

void FileProcessor::subWord(uint8_t *word) {
    int i;
    for (i = 0; i < 4; i++) {
        word[i] = AesConsts::SBOX[word[i] / 16][word[i] % 16];
    }
}

void FileProcessor::addRoundKey(std::vector<std::vector<uint8_t>> &state, std::vector<uint8_t> &expandedKey, size_t startFrom) {
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = state[i][j] ^ expandedKey[startFrom + i + 4 * j];
        }
    }
}

void FileProcessor::subBytes(std::vector<std::vector<uint8_t>> &state) {
    uint8_t t;
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = AesConsts::SBOX[t / 16][t % 16];
        }
    }
}

void FileProcessor::shiftRows(std::vector<std::vector<uint8_t>> &state) {
    shiftRow(state, 1, 1);
    shiftRow(state, 2, 2);
    shiftRow(state, 3, 3);
}

void FileProcessor::mixColumns(std::vector<std::vector<uint8_t>> &state) {
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

void FileProcessor::shiftRow(std::vector<std::vector<uint8_t>> &state, int rowIdx, int n) {
    std::vector<uint8_t> tmp = std::move(state[rowIdx]);
    std::rotate(tmp.begin(), tmp.begin() + n, tmp.end());
    state[rowIdx] = std::move(tmp);
}

std::vector<uint8_t>
FileProcessor::decryptBlock(std::vector<uint8_t> &in, std::vector<uint8_t> &key, size_t startFrom) {
    std::vector<uint8_t> out(4 * Nb, 0);
    std::vector<std::vector<uint8_t>> state = {
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
    };
    for(size_t i = 0; i < state.size(); i++)
        for(size_t j = 0; j < state[1].size(); j++)
            state[i][j] = in[startFrom + i + 4 * j];
    addRoundKey(state, key, Nr * 4 * Nb);
    for (int round = Nr - 1; round >= 1; round--) {
        invSubBytes(state);
        invShiftRows(state);
        addRoundKey(state, key, round * 4 * Nb);
        invMixColumns(state);
    }

    invSubBytes(state);
    invShiftRows(state);
    addRoundKey(state, key, 0);

    for(int i = 0; i < state.size(); i++)
        for(int j = 0; j < state[i].size(); j++)
            out[i + 4 * j] = state[i][j];

    return out;
}

void FileProcessor::invSubBytes(std::vector<std::vector<uint8_t>> &state) {
    uint8_t t;
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = AesConsts::INV_SBOX[t / 16][t % 16];
        }
    }
}

void FileProcessor::invShiftRows(std::vector<std::vector<uint8_t>> &state) {
    shiftRow(state, 1, 3);
    shiftRow(state, 2, 2);
    shiftRow(state, 3, 1);
}

void FileProcessor::invMixColumns(std::vector<std::vector<uint8_t>> &state) {
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

void FileProcessor::debugState(std::vector<std::vector<uint8_t>> &state) {
    static int c = 0;
    std::cout << "State " << c++ << ":" << std::endl;
    for(const auto& row: state)
    {
        for(auto col: row){
            std::cout << (int)col << ' ';
        }
        std::cout << std::endl;
    }
}

std::vector<uint8_t> FileProcessor::getRandomNonce() {
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0,255);
    std::vector<uint8_t> nonce(16, 0);
    for (uint8_t& d : nonce)
    {
        d = static_cast<uint8_t>(dist(rd) & 0xFF);
    }
    return nonce;
}

std::vector<uint8_t> FileProcessor::readNonce() {
    return std::vector<uint8_t>();
}

int main(int argc, char *argv[]) {
    Mode mode = getMode(argv[4]);
    std::string pwd(argv[3]);
    FileProcessor encrypt(argv[1], argv[2], mode, argv[3]);
    encrypt.process();
    FileProcessor decrypt("dest.txt", "decrypt.txt", DECRYPT, argv[3]);
    decrypt.process();
    return 0;
}

Mode getMode(const char *mode) {
    if (*mode == 'e')
        return ENCRYPT;
    if (*mode == 'd')
        return DECRYPT;
    throw std::invalid_argument("Wrong mode. e/d expected.");
}
