//
// Created by Romanv Denis on 24.08.2022.
//

#ifndef TESTOVOE_ZADANIE_AES256KEYEXPANDER_H
#define TESTOVOE_ZADANIE_AES256KEYEXPANDER_H

#include <stdexcept>
#include <utility>
#include "KeyExpander.h"

class Aes256KeyExpander : public KeyExpander {

public:
    /**
     * Number of rounds
     */
    static const int Nr = 14;
    /**
     * Words per key
     */
    static const int Nk = 8;
    /**
     * Bits per word
     */
    static const int bitsPerWord = 32;
    /**
     * Bytes per word
     */
    static const int bytesPerWord = bitsPerWord / 8;
    /**
     * Words per round of encryption
     */
    static const int wordsPerRound = 4;

    ~Aes256KeyExpander() override = default;

    /**
     *
     * @param key 256 bit key to produce a schedule. Throws std::invalid_argument if the key is of different length
     * @return key schedule for AES encryption (https://en.wikipedia.org/wiki/AES_key_schedule)
     */
     std::vector<uint8_t> keyExpansion(std::vector<uint8_t>& key) override;

private:
    /**
     * Checks if the key length is 256 bit. Throws std::invalid_argument if the key is of different length
     * @param key
     */
    void checkKey(std::vector<uint8_t>& key);

    /**
     * Rotates word by one byte left
     * @param word
     */
    static void rotWord(uint8_t word[4]);

    /**
     * Applies AES S-box to each of the four bytes of the word
     * @param word
     */
    static void subWord(uint8_t word[4]);
};


#endif //TESTOVOE_ZADANIE_AES256KEYEXPANDER_H
