#include <fstream>
#include <sstream>
#include "../header/AppProperties.h"

AppProperties::AppProperties(std::string sourceFile, std::string destFile, std::string password, uint32_t inputSize, Mode mode): sourceFile(std::move(sourceFile)), destFile(std::move(destFile)), inputSize(inputSize), mode(mode), password(std::move(password)) {

}

std::shared_ptr<AppProperties> AppProperties::build(int argc, char *argv[]) {
    checkParams(argc, argv);
    Mode mode = getMode(argv[4]);
    uint32_t is = getInputSizeParam();
    return std::make_shared<AppProperties>(AppProperties(argv[1], argv[2], argv[3], is, mode));
}

Mode AppProperties::getMode(const char *_mode) {
    if (*_mode == 'd')
        return DECRYPT;
    return ENCRYPT;
}

void AppProperties::checkParams(int argc, char *argv[]) {
    if (argc != 5)
        throw std::invalid_argument("Should pass 4 parameters. Source, dest, password, mode (e/d)");
    std::ifstream f(argv[1]);
    if (!f.good())
        throw std::invalid_argument("Source file doesn't exist");
}

uint32_t AppProperties::getInputSizeParam() {
    std::ifstream cfg("config.txt", std::ios_base::in);
    uint32_t result = 8196;
    if (cfg.good()){
        std::string line;
        std::getline(cfg, line);
        int tmp = std::stoi(line);
        if (tmp > 0 && tmp % 16 == 0)
            result = tmp;
    }
    return result;
}
