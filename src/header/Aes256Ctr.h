#ifndef TESTOVOE_ZADANIE_AES256CTR_H
#define TESTOVOE_ZADANIE_AES256CTR_H


#include <utility>
#include <vector>
#include <cstdint>
#include <string>

class Aes256Ctr {
public:
    /**
     * Processed block size in bytes
     */
    static const int blockSize = 16;

    explicit Aes256Ctr(std::string password, std::vector<uint8_t> nonce): password(std::move(password)), blockCounter(0), nonce(std::move(nonce)){}

    /**
     * Encrypts a block
     * @param in block to encrypt
     * @return encrypted block
     */
    std::vector<uint8_t> encrypt(std::vector<uint8_t>& in);
    /**
     * Decrypts a block
     * @param in block to decrypt
     * @return decrypted block
     */
    std::vector<uint8_t> decrypt(std::vector<uint8_t>& in);
    /**
     * Produces a random nonce
     * @return none
     */
    static std::vector<uint8_t> getRandomNonce();

    /**
     * Trys to read nonce in first block of file
     * @param source file
     * @return nonce
     */
    static std::vector<uint8_t> readNonce(std::ifstream& source);
private:
    /**
     * Password for encryption
     */
    const std::string password;
    /**
     * Number of processed blocks
     */
    uint32_t blockCounter;
    /**
     * Nonce
     */
    std::vector<uint8_t> nonce;
    /**
     * Produces 256 bit hash of a password
     * @return password hash
     */
    std::vector<uint8_t> passwordSha256();
    /**
     * Creates a block for encryption from nonce and password hash
     * @param counter number of block
     * @return block data
     */
    std::vector<uint8_t> makeCtrBlock(uint32_t counter);
};


#endif //TESTOVOE_ZADANIE_AES256CTR_H
