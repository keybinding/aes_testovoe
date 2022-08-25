#ifndef TESTOVOE_ZADANIE_FILEPROCESSOR_H
#define TESTOVOE_ZADANIE_FILEPROCESSOR_H


#include <string>
#include <functional>

class FileProcessor {
public:
    FileProcessor(std::string source, std::string dest);

    /**
     * Opens input and output, calls lambda that controls input and output
     * @param callBack
     */
    void process(const std::function <void (std::ifstream&, std::ofstream&)>& callBack);

    /**
     * Reads a bytes from file
     * @param file
     * @param byteCnt number of bytes to be read
     * @return
     */
    static std::vector<uint8_t> readChunk(std::ifstream &file, int byteCnt);
private:
    const std::string src;
    const std::string dst;
};


#endif //TESTOVOE_ZADANIE_FILEPROCESSOR_H
