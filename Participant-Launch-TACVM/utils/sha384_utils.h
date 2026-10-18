#ifndef SHA384_UTILS_H
#define SHA384_UTILS_H

#include <string>
#include <vector>

std::vector<unsigned char> sha384(
    const std::vector<unsigned char>& data
);

std::vector<unsigned char> sha384(
    const std::string& data
);

// Compute hex lowercase digest string (no prefix)
std::string sha384_hex(const std::string& data);

#endif
