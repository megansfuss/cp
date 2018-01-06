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

int main(int argc, char * argv[])
{
	char set = '0';
	if (argc > 1) {
		set = *argv[1];
	}

	switch (set) {
		case '1':
			if (exercise1()) {
				std::cout << "Exercise 1 Worked! :)" << std::endl;
			} else {
				std::cout << "Exercise 1 Failed... :(" << std::endl;
			}
			break;

		default:
			std::cout << "Unknown Option" << std::endl;
			break;
	}

	return EXIT_SUCCESS;
}
