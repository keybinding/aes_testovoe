//
// Created by Romanv Denis on 24.08.2022.
//

#ifndef TESTOVOE_ZADANIE_KEYEXPANDER_H
#define TESTOVOE_ZADANIE_KEYEXPANDER_H


#include <cstdint>
#include <vector>

class KeyExpander {
public:
    virtual ~KeyExpander() = default;
    virtual std::vector<uint8_t> keyExpansion(std::vector<uint8_t>& key) = 0;
};


#endif //TESTOVOE_ZADANIE_KEYEXPANDER_H
