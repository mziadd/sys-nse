// Small helpers shared by the native module.
//
// Notes:
// - This file is intentionally tiny and dependency-free.
// - The obfuscation here is NOT cryptography. It only hides obvious strings.
#pragma once

#include <string>
#include <cstdio>

namespace sys_utils {

// XOR key used for string literal obfuscation in this module.
static const unsigned char _v = 0xAC;

// XOR-decode a byte buffer into a std::string.
inline std::string d(const unsigned char* data, size_t len) {
  std::string s;
  s.reserve(len);
  for (size_t i = 0; i < len; ++i) s += static_cast<char>(data[i] ^ _v);
  return s;
}

// Minimal JSON string escaper (sufficient for the key/value payload).
inline std::string JsonEscape(const std::string& s) {
  std::string o;
  o.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"': o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\b': o += "\\b"; break;
      case '\f': o += "\\f"; break;
      case '\n': o += "\\n"; break;
      case '\r': o += "\\r"; break;
      case '\t': o += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04x", c);
          o += buf;
        } else {
          o += static_cast<char>(c);
        }
    }
  }
  return o;
}

} // namespace sys_utils

