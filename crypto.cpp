#include <algorithm>
#include <cctype>
#include <cfloat>
#include <cstdlib>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
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

bool exercise6()
{
	std::cout << "******************** CHALLENGE 1.6 ********************" << std::endl;

	std::string string1 = "this is a test";
	std::string string2 = "wokka wokka!!!";
	std::vector<uint8_t> string1_bytes;
	std::vector<uint8_t> string2_bytes;
	std::copy(string1.c_str(), string1.c_str() + string1.size(), back_inserter(string1_bytes));
	std::copy(string2.c_str(), string2.c_str() + string2.size(), back_inserter(string2_bytes));
	int32_t distance = hamming_distance(string1_bytes, string2_bytes);
	if (distance != 37) {
		std::cout << "Unexpected hamming distance " << hamming_distance << std::endl;
		return false;
	}

	std::ifstream f("6.txt");
	std::istream_iterator<uint8_t> start(f), end;
	std::vector<uint8_t> ciphertext(start, end);
	f.close();

	std::vector<uint8_t> decoded_ciphertext;
	if (base64_decode(ciphertext, decoded_ciphertext)) {
		std::cout << "Unable to decode cipher text" << std::endl;
		return false;
	}

	// For each key size, find the normalized hamming distance between
	// the first and second 
	// Map hamming distance to key size
	std::map<double,double> key_sizes;
	for (int i = 2; i <= 40; i++) {
		double temp_total = 0;
		int offset = 0;
		int pairs_to_test = 15;

		for (int j = 0; j < pairs_to_test; j++) {
			// 3a. Find the hamming distance between the first KEYSIZE bytes in the file
			// and the second KEYSIZE bytes in the file

			// Read file into 2 separate buffers
			std::vector<uint8_t> first_block;
			std::vector<uint8_t> second_block;

			first_block.insert(first_block.begin(), decoded_ciphertext.data(), decoded_ciphertext.data() + i + offset);
			second_block.insert(second_block.begin(), decoded_ciphertext.data() + i, decoded_ciphertext.data() + (2*i) + offset);
			offset += i;

			temp_total += (hamming_distance(first_block, second_block) / (double)i);
		}

		// 3b. Divide the result from 2 by the KEYSIZE (normalize)
		key_sizes.emplace(std::pair<double,double>(temp_total/pairs_to_test, (double)i));
	}

	// 4. Whichever KEYSIZE gives the smallest normalized distance is probably the
	// key. Try the smallest 2-3 values, or use 4 KEYSIZE blocks instead of 2 and
	// average the distances above.
	std::vector<std::vector<uint8_t>> blocks;
	auto it = key_sizes.begin();
	for (int key = 0; key < 1; key++) { // TODO 3
		int min_key_size = it++->second;
		printf("\nKey Size: %d\n", min_key_size);

		// 5. Break the ciphertext into blocks of KEYSIZE length
		uint32_t offset = 0;
		uint32_t remaining_bytes = decoded_ciphertext.size();
		blocks.clear();
		while (remaining_bytes > 0) {
			uint32_t bytes_to_copy = remaining_bytes > min_key_size ? min_key_size : remaining_bytes;
			std::vector<uint8_t> block;
			block.insert(block.begin(), decoded_ciphertext.data() + offset,
					decoded_ciphertext.data() + offset + bytes_to_copy);

			// Pad the block if it is too short
			if (block.size() != min_key_size) {
				block.resize(min_key_size);
			}

			offset += bytes_to_copy;
			remaining_bytes -= bytes_to_copy;
			blocks.push_back(block);
		}

		// Transpose
		std::vector<std::vector<uint8_t>> transposed_blocks;
		for (int i = 0; i < blocks[0].size(); i++) {
			transposed_blocks.push_back(std::vector<uint8_t>(blocks.size()));
		}

		for (int i = 0; i < blocks.size(); i++) {
			for (int j = 0; j < blocks[0].size(); j++) {
				transposed_blocks[j][i] = blocks[i][j];
			}
		}

		// 7. Solve each block as if it was single-character XOR.
		std::vector<uint8_t> repeating_key_xor;
		for (auto it = transposed_blocks.begin(); it != transposed_blocks.end(); it++) {
			std::vector<uint8_t> block = *it;

			std::pair<char, float> pair = determine_most_likely_single_xor_key(block);
			repeating_key_xor.push_back(pair.first);
		}

		std::vector<uint8_t> result;
		repeating_xor(decoded_ciphertext, repeating_key_xor, result);
		std::string decrypted = std::string(result.begin(), result.end());

		if (decrypted.find("Play that funky music") != std::string::npos) {
			std::cout << "Key: " << std::string(repeating_key_xor.begin(),
				repeating_key_xor.end()) << std::endl;
			std::cout << decrypted << std::endl;
			return true;
		}
	}

	return false;
}

bool exercise7()
{
	std::string key_str = "YELLOW SUBMARINE";

	std::ifstream f("7.txt");
	std::istream_iterator<uint8_t> start(f), end;
	std::vector<uint8_t> ciphertext(start, end);
	f.close();

	std::vector<uint8_t> decoded_ciphertext;
	if (base64_decode(ciphertext, decoded_ciphertext)) {
		std::cout << "Unable to decode cipher text" << std::endl;
		return false;
	}

	for (size_t i = 0; i < decoded_ciphertext.size(); i++) {
		printf("%02x", decoded_ciphertext[i]);
	}
	std::cout << std::endl;

	std::vector<uint8_t> key(key_str.begin(), key_str.end());
	std::vector<uint8_t> plaintext;
	if (decrypt_aes_128_ecb(decoded_ciphertext, key, plaintext) < 0) {
		std::cout << "Unable to decrypt message" << std::endl;
		return false;
	}

	std::string decrypted = std::string(plaintext.begin(), plaintext.end());
	if (decrypted.find("Play that funky music") != std::string::npos) {
		std::cout << decrypted << std::endl;

		std::vector<uint8_t> new_encrypted;
		if (encrypt_aes_128_ecb(plaintext, key, new_encrypted) < 0) {
			std::cout << "Unable to re-encrypt" << std::endl;
		}

		for (size_t i = 0; i < new_encrypted.size(); i++) {
			printf("%02x", new_encrypted[i]);
		}
		std::cout << std::endl;

		if (decoded_ciphertext == new_encrypted) {
			std::cout << "Successfully re-encrypted ciphertext!" << std::endl;
			return true;
		}

		return false;
	
	}

	return false;
}

bool exercise8()
{
	std::ifstream f("8.txt");
	std::string line;
	std::map<int,std::string> repeats;
	while (std::getline(f, line)) {
		std::vector<uint8_t> bytes;
		if (hex_to_bytes(line, bytes)) {
			std::cout << "Unable to convert " << line << " to bytes" << std::endl;
			return false;
		}

		// For each 16-byte block, see if it exists elsewhere
		size_t bytes_remaining = bytes.size();
		auto start = bytes.begin();
		int num_matches = 0;
		while(bytes_remaining > 0) {
			size_t bytes_to_copy = bytes_remaining > 16 ? 16 : bytes_remaining;
			bytes_remaining -= bytes_to_copy;

			// Break into 16-bytes block
			std::vector<uint8_t> sub;
			sub.insert(sub.begin(), start, start + bytes_to_copy);
			start += bytes_to_copy;

			// Check remaining vector for it
			if (std::search(start, bytes.end(), sub.begin(), sub.end()) != bytes.end()) {
				num_matches++;
			}
		}

		if (num_matches > 0) {
			repeats.emplace(std::pair<int,std::string>(num_matches, line));
		}
	}

	std::cout << std::endl;

	if (repeats.size() > 0) {
		for (auto it = repeats.begin(); it != repeats.end(); it++) {
			std::cout << "Likely ECB Encrypted String: " << it->second << std::endl;
			std::cout << "\tRepeats: " << it->first << std::endl;
		}

		return true;
	}

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

			case '6':
				if (exercise6()) {
					std::cout << "Exercise 6 Worked! :)" << std::endl;
				} else {
					std::cout << "Exercise 6 Failed... :(" << std::endl;
				}
				break;

			case '7':
				if (exercise7()) {
					std::cout << "Exercise 7 Worked! :)" << std::endl;
				} else {
					std::cout << "Exercise 7 Failed... :(" << std::endl;
				}
				break;

			case '8':
				if (exercise8()) {
					std::cout << "Exercise 8 Worked! :)" << std::endl;
				} else {
					std::cout << "Exercise 8 Failed... :(" << std::endl;
				}
				break;

			default:
				std::cout << "Unknown Option" << std::endl;
				break;
		}
	}

	return EXIT_SUCCESS;
}
