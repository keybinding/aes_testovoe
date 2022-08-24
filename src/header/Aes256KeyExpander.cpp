//
// Created by Romanv Denis on 24.08.2022.
//

#include "Aes256KeyExpander.h"
#include "aes_consts.h"

std::vector<uint8_t> Aes256KeyExpander::keyExpansion(std::vector<uint8_t>& key) {
    uint8_t temp[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t rcon[4] = {0x00, 0x00, 0x00, 0x00};
    uint8_t ci[10] = {0x01, 0x02, 0x04, 0x08, 0x10,0x20, 0x40, 0x80, 0x1b, 0x36};
    std::vector<uint8_t> expandedKey(wordsPerRound * (Nr + 1) * bytesPerWord, 0);
    for(size_t i = 0; i < wordsPerRound * (Nr + 1); i++) {
        size_t beg = bytesPerWord * i;
        if (i < Nk) {
            for(size_t j = beg; j < beg + bytesPerWord; j++)
                expandedKey[j] = key[j];
        }
        else if (i % Nk == 0) {
            for(size_t im1 = beg - bytesPerWord, k = 0; im1 < beg; im1++, k++)
                temp[k] = expandedKey[im1];
            rotWord(temp);
            subWord(temp);
            rcon[0] = ci[i / Nk - 1];
            for(size_t j = beg, k = 0; j < beg + bytesPerWord; j++, k++)
                expandedKey[j] = expandedKey[j - Nk * bytesPerWord] ^ temp[k] ^ rcon[k];
        }
        else if (i % Nk == 4){
            for(size_t im1 = beg - bytesPerWord, k = 0; im1 < beg; im1++, k++)
                temp[k] = expandedKey[im1];
            subWord(temp);
            for(size_t j = beg, k = 0; j < beg + bytesPerWord; j++, k++)
                expandedKey[j] = expandedKey[j - Nk * bytesPerWord] ^ temp[k];
        }
        else {
            for(size_t im1 = beg - bytesPerWord, k = 0; im1 < beg; im1++, k++)
                temp[k] = expandedKey[im1];
            for(size_t j = beg, k = 0; j < beg + bytesPerWord; j++, k++)
                expandedKey[j] = expandedKey[j - Nk * bytesPerWord] ^ temp[k];
        }
    }
    return expandedKey;
}

void Aes256KeyExpander::checkKey(std::vector<uint8_t>& key) {
    if (key.size() != bitsPerWord * Nk)
        throw std::invalid_argument("Key must be 256 bits long");
}

void Aes256KeyExpander::rotWord(uint8_t *word) {
    uint8_t c = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = c;
}

void Aes256KeyExpander::subWord(uint8_t *word) {
    int i;
    for (i = 0; i < 4; i++) {
        word[i] = AesConsts::SBOX[word[i] / 16][word[i] % 16];
    }
}