#include <iostream>
#include <utility>
#include <fstream>
#include <vector>
#include <random>
#include "include/SHA256.h"
#include "src/header/aes_consts.h"
#include "src/header/Aes256KeyExpander.h"

#define CHUNK_SIZE 1024
#define BLOCK_SIZE 16

enum Mode {ENCRYPT, DECRYPT};

class CtrModeProcessor {

};

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

    static std::vector<uint8_t> encryptBlock(std::vector<uint8_t> &in, std::vector<uint8_t> &key);
    static std::vector<uint8_t> decryptBlock(std::vector<uint8_t> &in, std::vector<uint8_t> &key);
    static std::vector<uint8_t> readChunk(std::ifstream &file, int byteCnt);

    std::vector<uint8_t> passwordSha256(std::string const&basicString);

    static void addRoundKey(std::vector<std::vector<uint8_t>> &state, std::vector<uint8_t> &expandedKey, size_t startFrom);

    static void subBytes(std::vector<std::vector<uint8_t>> &state);

    static void shiftRows(std::vector<std::vector<uint8_t>> &state);

    static void mixColumns(std::vector<std::vector<uint8_t>> &state);

    static void shiftRow(std::vector<std::vector<uint8_t>> &state, int rowIdx, int n);

    static void invSubBytes(std::vector<std::vector<uint8_t>> &state);

    static void invShiftRows(std::vector<std::vector<uint8_t>> &state);

    static void invMixColumns(std::vector<std::vector<uint8_t>> &state);

    static void debugState(std::vector<std::vector<uint8_t>> &state);

    static std::vector<uint8_t> getRandomNonce();

    static std::vector<uint8_t> readNonce(std::ifstream& source);

    static void saveNonce(std::vector<uint8_t>& nonce, std::ofstream& out);

    static std::vector<uint8_t> makeCtrBlock(std::vector<uint8_t> &nonce, uint32_t counter);
};



FileProcessor::FileProcessor(std::string source, std::string dest, Mode mode, std::string password): src(std::move(source)), dst(std::move(dest)), mode(mode), pwd(std::move(password)) {
}

Mode getMode(const char *mode);

void FileProcessor::process() {
    std::ifstream file(src, std::ios_base::binary | std::ios_base::in );
    std::ofstream outFile(dst, std::ios_base::binary | std::ios_base::out);
    auto nonce = mode == ENCRYPT ? getRandomNonce() : readNonce(file);
    if (mode == ENCRYPT)
        saveNonce(nonce, outFile);
    auto key = passwordSha256(pwd);
    Aes256KeyExpander keyExpander;
    std::vector<uint8_t> expandedKey = keyExpander.keyExpansion(key);
    while(!file.eof()) {
        uint32_t blocksCounter = 1;
        std::vector<uint8_t> chunk = readChunk(file, CHUNK_SIZE);
        std::vector<uint8_t> out(chunk.size(), 0);
        size_t blocks = chunk.size() / BLOCK_SIZE;
        for (int i = 0; i < blocks; i++) {
            std::vector<uint8_t> counterBlock = makeCtrBlock(nonce, blocksCounter);
            std::vector<uint8_t> block = encryptBlock(counterBlock, expandedKey);
            for (int j = 0; j < BLOCK_SIZE; ++j)
                out[i * BLOCK_SIZE + j] = block[j] ^ chunk[i * BLOCK_SIZE + j];
            blocksCounter++;
        }
        int bytesLeft = chunk.size() % BLOCK_SIZE;
        if (bytesLeft != 0) {
            std::vector<uint8_t> counterBlock = makeCtrBlock(nonce, blocksCounter);
            std::vector<uint8_t> block = encryptBlock(counterBlock, expandedKey);
            for (int j = 0; j < bytesLeft; ++j)
                out[blocks * BLOCK_SIZE + j] = block[j] ^ chunk[blocks * BLOCK_SIZE + j];
        }
        outFile.write((const char*)out.data(), out.size());
    }
}

std::vector<uint8_t>
FileProcessor::encryptBlock(std::vector<uint8_t> &in, std::vector<uint8_t> &expandedKey) {
    std::vector<uint8_t> out(4 * Nb, 0);
    std::vector<std::vector<uint8_t>> state = {
        std::vector<uint8_t>(4, 0),
        std::vector<uint8_t>(4, 0),
        std::vector<uint8_t>(4, 0),
        std::vector<uint8_t>(4, 0),
    };
    for(size_t i = 0; i < state.size(); i++)
        for(size_t j = 0; j < state[1].size(); j++)
            state[i][j] = in[i + 4 * j];

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

std::vector<uint8_t> FileProcessor::readChunk(std::ifstream& file, int byteCnt) {
    char out[byteCnt];
    file.read(out, byteCnt);
    size_t n = file.gcount();
    std::vector<uint8_t> result;
    result.reserve(byteCnt);
    for(size_t i = 0; i < n; i++){
        result.push_back(out[i]);
    }
    return result;
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
FileProcessor::decryptBlock(std::vector<uint8_t> &in, std::vector<uint8_t> &key) {
    std::vector<uint8_t> out(4 * Nb, 0);
    std::vector<std::vector<uint8_t>> state = {
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
            std::vector<uint8_t>(4, 0),
    };
    for(size_t i = 0; i < state.size(); i++)
        for(size_t j = 0; j < state[1].size(); j++)
            state[i][j] = in[i + 4 * j];
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

std::vector<uint8_t> FileProcessor::readNonce(std::ifstream& source) {
    auto nonce = readChunk(source, BLOCK_SIZE);
    if (nonce.size() != BLOCK_SIZE)
        throw std::invalid_argument("Не удалось прочитать nonce");
    return nonce;
}

void FileProcessor::saveNonce(std::vector<uint8_t>& nonce, std::ofstream& out) {
    out.write((const char*)nonce.data(), nonce.size());
}

std::vector<uint8_t> FileProcessor::makeCtrBlock(std::vector<uint8_t> &nonce, uint32_t counter) {
    std::vector<uint8_t> ctrBlock = std::vector<uint8_t>(BLOCK_SIZE, 0);
    if (nonce.size() != BLOCK_SIZE)
        throw std::invalid_argument("Nonce length must be 16 byte");
    std::copy(nonce.begin(), nonce.end(), ctrBlock.begin());
    for(int i = 0; i < 4; i++){
        counter = counter >> (i * 8);
        ctrBlock[i] = counter & 0xff;
    }
    return ctrBlock;
}

int main(int argc, char *argv[]) {
    Mode mode = getMode(argv[4]);
    std::string pwd(argv[3]);
    FileProcessor encrypt(argv[1], argv[2], mode, argv[3]);
    encrypt.process();
    return 0;
}

Mode getMode(const char *mode) {
    if (*mode == 'e')
        return ENCRYPT;
    if (*mode == 'd')
        return DECRYPT;
    throw std::invalid_argument("Wrong mode. e/d expected.");
}
