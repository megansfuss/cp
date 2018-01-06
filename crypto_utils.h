#include <cstdint>
#include <string>
#include <vector>

int hex_to_bytes(const std::string & input, std::vector<uint8_t> & bytes);
void base64_encode(const std::vector<uint8_t> & bytes, std::vector<char> & output);
void fixed_xor(const std::vector<uint8_t> & bytes1, const std::vector<uint8_t> & bytes2,
	std::vector<uint8_t> & output);
void determine_frequencies(const std::vector<uint8_t> & bytes, std::map<char,int> & map);
