#ifndef CANONICAL_JSON_H
#define CANONICAL_JSON_H

#include <string>
#include <nlohmann/json.hpp>

// Produce canonical JSON string with sorted object keys, preserved array order,
// and compact separators (no spaces). Returns true on success, false on error
// with an error message in `error_msg` when provided.
bool canonical_json_string_from_json(
    const nlohmann::json& input,
    std::string* output,
    std::string* error_msg = nullptr
);

// Parse either JSON or YAML text and produce canonical JSON string.
bool canonical_json_string_from_text(
    const std::string& text,
    std::string* output,
    std::string* error_msg = nullptr
);

#endif
