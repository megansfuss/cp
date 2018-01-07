#include <cctype>
#include <cfloat>
#include <cstdlib>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <vector>

#include "crypto_utils.h"

bool exercise1()
{
	std::cout << "******************** CHALLENGE 1 ********************" << std::endl;

	const std::string input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	std::vector<uint8_t> bytes;
	if (hex_to_bytes(input, bytes)) {
		return false;
	}

	std::vector<char> output;
	base64_encode(bytes, output);

	std::string test_string(output.begin(), output.end());
	std::cout << "Encodeded string: " << test_string << std::endl;

	// TEST IT WORKS
	const std::string expected_result = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
	return (test_string == expected_result);
}

bool exercise2()
{
	std::cout << "******************** CHALLENGE 2 ********************" << std::endl;

	std::string input1 = "1c0111001f010100061a024b53535009181c";
	std::string input2 = "686974207468652062756c6c277320657965";
	std::string expected = "746865206b696420646f6e277420706c6179";

	std::vector<uint8_t> bytes1;
	if (hex_to_bytes(input1, bytes1)) {
		std::cout << "Unable to convert the first input string to bytes" << std::endl;
		return false;
	}

	std::vector<uint8_t> bytes2;
	if (hex_to_bytes(input2, bytes2)) {
		std::cout << "Unable to convert the second input string to bytes" << std::endl;
		return false;
	}

	// perform fixed xor
	std::vector<uint8_t> output;
	fixed_xor(bytes1, bytes2, output);

	// confirm fixed xor worked
	std::vector<uint8_t> expected_bytes;
	if (hex_to_bytes(expected, expected_bytes)) {
		return false;
	}

	return (output == expected_bytes);
}

bool exercise3()
{
	std::cout << "******************** CHALLENGE 3 ********************" << std::endl;

	const std::string input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
	std::vector<uint8_t> bytes;
	if (hex_to_bytes(input, bytes)) {
		return false;
	}

	std::pair<char, float> min_result = determine_most_likely_single_xor_key(bytes);

	std::cout << "KEY: " << min_result.first << std::endl;
	std::cout << "Result: " << min_result.second << std::endl;

	std::vector<uint8_t> xor_result;
	std::vector<uint8_t> key(bytes.size(), min_result.first);
	fixed_xor(bytes, key, xor_result);
	std::string result_string = std::string(xor_result.begin(), xor_result.end());
	std::cout << "XOR Result: " << result_string << std::endl;

	std::string expected_string = "Cooking MC's like a pound of bacon";

	return (result_string == expected_string); 
}

bool exercise4()
{
	std::cout << "******************** CHALLENGE 4 ********************" << std::endl;

	std::string most_likely_line;
	char most_likely_key;
	float most_likely_chi_result = FLT_MAX;

	std::ifstream f("4.txt");
	std::string line;
	while (std::getline(f, line)) {
		std::vector<uint8_t> bytes;
		if (hex_to_bytes(line, bytes)) {
			return false;
		}

		std::pair<char, float> min_result = determine_most_likely_single_xor_key(bytes);
		if (most_likely_chi_result >= min_result.second) {
			most_likely_chi_result = min_result.second;
			most_likely_key = min_result.first;
			most_likely_line = line;
		}
	}

	// Output what the most likely line is
	std::vector<uint8_t> bytes;
	if (hex_to_bytes(most_likely_line, bytes)) {
			return false;
	}

	std::vector<uint8_t> xor_result;
	std::vector<uint8_t> key(bytes.size(), (char)most_likely_key);
	fixed_xor(bytes, key, xor_result);
	std::string result_string = std::string(xor_result.begin(), xor_result.end());
	std::cout << "KEY: " << most_likely_key << std::endl;
	std::cout << "Result: " << most_likely_chi_result << std::endl;
	std::cout << "XOR Result: " << result_string << std::endl;

	std::string expected_string = "Now that the party is jumping\n";
	return (result_string == expected_string);
}

bool exercise5()
{
	std::cout << "******************** CHALLENGE 1.5 ********************" << std::endl;

	const std::string stanza = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
	const std::string key = "ICE";
	const std::string expected_string = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

	std::vector<uint8_t> stanza_bytes;
	std::copy(stanza.c_str(), stanza.c_str() + stanza.size(), back_inserter(stanza_bytes));

	std::vector<uint8_t> key_bytes;
	std::copy(key.c_str(), key.c_str() + key.size(), back_inserter(key_bytes));

	std::vector<uint8_t> result;
	repeating_xor(stanza_bytes, key_bytes, result);

	std::vector<uint8_t> expected_bytes;
	if (hex_to_bytes(expected_string, expected_bytes)) {
		return false;
	}

	return (result == expected_bytes);
}

int main(int argc, char * argv[])
{
	for (int i = 1; i < argc; i++ ) {
		char set = *argv[i];
		switch (set) {
			case '1':
				if (exercise1()) {
					std::cout << "Exercise 1 Worked! :)" << std::endl;
				} else {
					std::cout << "Exercise 1 Failed... :(" << std::endl;
				}
				break;

			case '2':
				if (exercise2()) {
					std::cout << "Exercise 2 Worked! :)" << std::endl;
				} else {
					std::cout << "Exercise 2 Failed... :(" << std::endl;
				}
				break;

			case '3':
				if (exercise3()) {
					std::cout << "Exercise 3 Worked! :)" << std::endl;
				} else {
					std::cout << "Exercise 3 Failed... :(" << std::endl;
				}
				break;

			case '4':
				if (exercise4()) {
					std::cout << "Exercise 4 Worked! :)" << std::endl;
				} else {
					std::cout << "Exercise 4 Failed... :(" << std::endl;
				}
				break;

			case '5':
				if (exercise5()) {
					std::cout << "Exercise 5 Worked! :)" << std::endl;
				} else {
					std::cout << "Exercise 5 Failed... :(" << std::endl;
				}
				break;

			default:
				std::cout << "Unknown Option" << std::endl;
				break;
		}
	}

	return EXIT_SUCCESS;
}
