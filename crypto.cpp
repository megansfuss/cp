#include <cstdlib>
#include <cstdint>
#include <iostream>
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
	const std::string input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
	std::vector<uint8_t> bytes;
	if (hex_to_bytes(input, bytes)) {
		return false;
	}

	std::map<char, int> freq;
	determine_frequencies(bytes, freq);

	return false;
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

			case '3';
				if (exercise3()) {
					std::cout << "Exercise 3 Worked! :)" << std::endl;
				} else {
					std::cout << "Exercise 3 Failed... :(" << std::endl;
				}
				break;

			default:
				std::cout << "Unknown Option" << std::endl;
				break;
		}
	}

	return EXIT_SUCCESS;
}
