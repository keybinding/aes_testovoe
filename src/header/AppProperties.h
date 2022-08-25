#ifndef TESTOVOE_ZADANIE_APPPROPERTIES_H
#define TESTOVOE_ZADANIE_APPPROPERTIES_H


#include <string>
#include <memory>

enum Mode {ENCRYPT, DECRYPT};

struct AppProperties {
    /**
     * File to encrypt
     */
    const std::string sourceFile;
    /**
     * File to decrypt
     */
    const std::string destFile;
    /**
     * Bytes read from input at a time
     */
    const int inputSize;
    /**
     * Mode encryption/decryption (e/d)
     */
    const Mode mode;
    /**
     * Encryption password
     */
    const std::string password;

    /**
     * Reads properties from main argv and from config.txt. Uses default mode Encryption, and default
     * @param argc number of params
     * @param argv values of params
     * @return properties
     */
    static std::shared_ptr<AppProperties> build(int argc, char *argv[]);
private:
    AppProperties(std::string sourceFile, std::string destFile, std::string password, int inputSize, Mode mode);
    static Mode getMode(const char *mode);
};


#endif //TESTOVOE_ZADANIE_APPPROPERTIES_H
