#include "utils.h"
#include <sstream>
#include <iostream>

uint64_t hex_string_to_uint(std::string in) {
  uint64_t x;
  std::stringstream ss;
  ss << std::hex << in ;
  ss >> x;
  return(x);
}
std::string uint_to_hex_string(uint64_t in) {
  std::stringstream ss;
  ss << std::hex << in;
  return ss.str();
}

