#ifndef SHA256_UTILS_H
#define SHA256_UTILS_H

#include <string>
#include <vector>

std::vector<unsigned char> sha256(
    const std::vector<unsigned char>& data
);

std::vector<unsigned char> sha256(
    const std::string& data
);

#endif