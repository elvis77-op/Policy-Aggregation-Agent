#include "canonical_json.h"

#include <algorithm>
#include <sstream>

#include <yaml-cpp/yaml.h>

using json = nlohmann::json;

static json normalize_json(const json& in) {
    if (in.is_object()) {
        json out = json::object();
        std::vector<std::string> keys;
        for (auto it = in.begin(); it != in.end(); ++it) {
            keys.push_back(it.key());
        }
        std::sort(keys.begin(), keys.end());
        for (const auto& k : keys) {
            out[k] = normalize_json(in.at(k));
        }
        return out;
    }

    if (in.is_array()) {
        json out = json::array();
        for (const auto& item : in) {
            out.push_back(normalize_json(item));
        }
        return out;
    }

    return in;
}

static json yaml_node_to_json(const YAML::Node& node) {
    if (!node) return json();

    if (node.IsScalar()) {
        return json(node.Scalar());
    }

    if (node.IsSequence()) {
        json arr = json::array();
        for (const auto& el : node) {
            arr.push_back(yaml_node_to_json(el));
        }
        return arr;
    }

    if (node.IsMap()) {
        json obj = json::object();
        for (const auto& kv : node) {
            const auto key = kv.first.Scalar();
            obj[key] = yaml_node_to_json(kv.second);
        }
        return obj;
    }

    return json();
}

bool canonical_json_string_from_json(
    const json& input,
    std::string* output,
    std::string* error_msg
) {
    if (!output) return false;
    try {
        json normalized = normalize_json(input);
        // dump() uses compact separators by default
        *output = normalized.dump();
        return true;
    } catch (const std::exception& e) {
        if (error_msg) *error_msg = e.what();
        return false;
    }
}

bool canonical_json_string_from_text(
    const std::string& text,
    std::string* output,
    std::string* error_msg
) {
    if (!output) return false;

    // Try JSON first
    try {
        json parsed = json::parse(text);
        return canonical_json_string_from_json(parsed, output, error_msg);
    } catch (const std::exception&) {
        // fallthrough to YAML
    }

    try {
        YAML::Node node = YAML::Load(text);
        json converted = yaml_node_to_json(node);
        return canonical_json_string_from_json(converted, output, error_msg);
    } catch (const std::exception& e) {
        if (error_msg) *error_msg = e.what();
        return false;
    }
}
