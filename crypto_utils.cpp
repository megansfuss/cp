#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "crypto_utils.h"

/* Conversion from value to base64 character */
const char BASE64[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};


/* Binary 111111 (lowest 6 bits set only) */ 
const uint32_t MASK = 0x3F;

int hex_to_bytes(const std::string & input, std::vector<uint8_t> & bytes)
{
	if (input.size() % 2 != 0) {
		std::cout << "Input string must be byte aligned" << std::endl;
		return -1;
	}

	char * endptr;
	char tmp[3];
	tmp[2] = '\0';
	for (int i = 0; i < input.size()/2; i++) {
		tmp[0] = input.at(i*2);
		tmp[1] = input.at(i*2 + 1);
		uint8_t value = strtol(tmp, &endptr, 16);
		if (*endptr != '\0') {
			std::cout << "Invalid hex string" << std::endl;
			return -1;
		}
		bytes.push_back(value);
	}

	return 0;

}

void base64_encode(const std::vector<uint8_t> & bytes, std::vector<char> & output)
{
	// ceil(len/3)
	int rounds = (bytes.size() + (3-1)) / 3;

	bool use_pad_1 = false;
	bool use_pad_2 = false;
	for (int round = 0; round < rounds; round++) {
		// Determine if any padding is needed
		if (round + 1 == rounds) { 
			if (bytes.size() % 3 == 1) {
				use_pad_1 = true;
				use_pad_2 = true;
			} else if (bytes.size() % 3 == 2) {
				use_pad_2 = true;
			}
		}

		// Find value of each 24-bit word (3 bytes)
		int firstbyte = bytes.at(round*3 + 0) << 16;
		int secondbyte = use_pad_1 ? 0 : bytes.at(round*3 + 1) << 8;
		int thirdbyte = use_pad_2 ? 0 : bytes.at(round*3 + 2);

		int fullnum = firstbyte + secondbyte + thirdbyte;

		// Split into 6-bit words
		int n1 = (fullnum >> 18) & MASK;
		int n2 = (fullnum >> 12) & MASK;
		int n3 = (fullnum >> 6) & MASK;
		int n4 = fullnum & MASK;

		output.push_back(BASE64[n1]);
		output.push_back(BASE64[n2]);
		output.push_back(use_pad_1 ? '=' : BASE64[n3]);
		output.push_back(use_pad_2 ? '=' : BASE64[n4]);
	}
}

void fixed_xor(const std::vector<uint8_t> & bytes1, const std::vector<uint8_t> & bytes2,
	std::vector<uint8_t> & output)
{
	output.clear();
	if (bytes1.size() != bytes2.size()) {
		std::cout << "Fixed XOR inputs must be of the same size." << std::endl;
		return;
	}

	auto it1 = bytes1.begin();
	auto it2 = bytes2.begin();
	for ( ; it1 != bytes1.end(); ++it1, ++it2) {
		output.push_back(*it1 ^ *it2);
	}
}

void determine_frequencies(const std::vector<uint8_t> & bytes, std::map<char, float> & map)
{
	for (auto pair = ascii_freq.begin(); pair != ascii_freq.end(); ++pair) {
		float total = 0;
		for (auto it = bytes.begin(); it != bytes.end(); ++it) {
			if (pair->first == (char)*it) {
				total++;
			}
		}

		map.emplace(std::pair<char, float>(pair->first, total));
	}
}

float determine_chi_squared_result(const std::map<char, float> & freq, size_t len)
{
	float chi_squared_result = 0;
	float total_actual_characters = 0;
	for (auto pair = freq.begin(); pair != freq.end(); ++pair) {
		char cur = pair->first;
		float expected = ascii_freq.at(cur) * len;
		float actual = pair->second;
		total_actual_characters += actual;
		chi_squared_result += (pow(actual-expected, 2.0) / expected);
	}

	// Determine percentage of characters that are unexpected
	float unexpected_decimal = 1.0;
	for (auto pair = ascii_freq.begin(); pair != ascii_freq.end(); ++pair) {
		unexpected_decimal -= pair->second;
	}
	float unexpected_expected_characters = unexpected_decimal * len;
	float unexpected_actual_characters = len - total_actual_characters;

	chi_squared_result += pow(unexpected_actual_characters-unexpected_expected_characters, 2.0) / unexpected_expected_characters;
	return chi_squared_result;
}

std::pair<char, float> determine_most_likely_single_xor_key(const std::vector<uint8_t> bytes)
{
	std::pair<char, float> min_result = std::pair<char,float>(' ', FLT_MAX);
	for (int i = 32; i < 128; i++ ) {
		std::vector<uint8_t> key(bytes.size(), i);
		std::vector<uint8_t> xor_result;
		fixed_xor(bytes, key, xor_result);
		std::transform(xor_result.begin(), xor_result.end(), xor_result.begin(), ::tolower);

		std::map<char, float> freq;
		determine_frequencies(xor_result, freq);

		float chi_squared_result = determine_chi_squared_result(freq, xor_result.size());

		if (chi_squared_result <= min_result.second) {
			min_result = std::pair<char, float>((char)i, chi_squared_result);
		}
	}

	return min_result;
}

void repeating_xor(const std::vector<uint8_t> & buffer, const std::vector<uint8_t> & key, std::vector<uint8_t> & result)
{
	for (size_t i = 0; i < buffer.size(); i++) {
		int key_index = i % key.size();
		result.push_back(buffer[i] ^ key[key_index]);
	}
}
