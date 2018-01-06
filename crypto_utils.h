#include <cstdint>
#include <string>
#include <vector>

int hex_to_bytes(const std::string & input, std::vector<uint8_t> & bytes);
void base64_encode(const std::vector<uint8_t> & bytes, std::vector<char> & output);
