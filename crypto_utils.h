#include <cstdint>
#include <map>
#include <string>
#include <vector>

static const std::map<char, float> ascii_freq = {
	{' ', .18288},
	{'e', .10266},
	{'t', .07517},
	{'a', .06532},
	{'o', .06160},
	{'n', .05712},
	{'i', .05668},
	{'s', .05317},
	{'r', .04988},
	{'h', .04979},
	{'l', .03318},
	{'d', .03283},
	{'u', .02276},
	{'c', .02234},
	{'m', .02027},
	{'f', .01983},
	{'w', .01704},
	{'g', .01625},
	{'p', .01504},
	{'y', .01428},
	{'b', .01259},
	{'v', .00796},
	{'k', .00561},
	{'x', .00141},
	{'j', .00095},
	{'q', .00084},
	{'z', .00051},
};



int hex_to_bytes(const std::string & input, std::vector<uint8_t> & bytes);
void base64_encode(const std::vector<uint8_t> & bytes, std::vector<char> & output);
void fixed_xor(const std::vector<uint8_t> & bytes1, const std::vector<uint8_t> & bytes2,
	std::vector<uint8_t> & output);
void determine_frequencies(const std::vector<uint8_t> & bytes, std::map<char,float> & map);
float determine_chi_squared_result(const std::map<char, float> & freq, size_t len);
std::pair<char, float> determine_most_likely_single_xor_key(const std::vector<uint8_t> bytes);
void repeating_xor(const std::vector<uint8_t> & buffer, const std::vector<uint8_t> & key, std::vector<uint8_t> & result);
int32_t hamming_distance(const std::vector<uint8_t> & input1, const std::vector<uint8_t> & input2);
int32_t base64_decode(const std::vector<uint8_t> & encoded, std::vector<uint8_t> & bytes);
int encrypt_aes_128_ecb(const std::vector<uint8_t> & plaintext,	const std::vector<uint8_t> & key, std::vector<uint8_t> & ciphertext);
int decrypt_aes_128_ecb(const std::vector<uint8_t> & ciphertext, const std::vector<uint8_t> & key, std::vector<uint8_t> & plaintext);
std::vector<uint8_t> pad_string(const std::string & input, size_t multiple);
