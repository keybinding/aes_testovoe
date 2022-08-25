#include "AppProperties.h"

AppProperties::AppProperties(std::string sourceFile, std::string destFile, std::string password, int inputSize, Mode mode): sourceFile(std::move(sourceFile)), destFile(std::move(destFile)), inputSize(inputSize), mode(mode), password(std::move(password)) {

}

std::shared_ptr<AppProperties> AppProperties::build(int argc, char *argv[]) {
    Mode mode = getMode(argv[4]);
    std::string pwd(argv[3]);
    return std::make_shared<AppProperties>(AppProperties(argv[1], argv[2], pwd, 8196, mode));
}

Mode AppProperties::getMode(const char *_mode) {
    if (*_mode == 'd')
        return DECRYPT;
    return ENCRYPT;
}
