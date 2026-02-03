//TODO: Create json database 
//Create verify password function and hash main password
//Crypt the other passwords
//I will make it tomorrow
#ifndef BACKEND_H
#define BACKEND_H

#include "sodium_init.h"
#include "imgui.h"
#include "json.hpp"

#include <string>
#include <vector>


using json = nlohmann::json;
//class for backend functions:
class Backend {
private:
	json database;
	std::array<unsigned char, crypto_secretbox_KEYBYTES> current_session_key;
	Sodium_Init sodium;
public:
	//encode:
	std::string base64_encode(const unsigned char* data, size_t len);
	std::vector<unsigned char> base64_decode(const std::string& b64);
	
	std::string hash_password(const char* password);
	//Encrypt key:
	std::array<unsigned char, crypto_secretbox_KEYBYTES>
		derive_key(const std::string& password, const unsigned char* salt);
	bool verify(const char* password, std::string hashed);
	bool log_in(const char* name, const char* password);
	bool registration(const char* name, const char* password, const char* key);
	bool unlock_vault(const char* username, const char* input_key);
	//encrypt password:
	std::string encrypt_password(
		const std::string& plaintext,
		const std::array<unsigned char, crypto_secretbox_KEYBYTES>& key,
		std::string& out_nonce_b64);

	std::string decrypt_password(
		const std::string& cipher_b64,
		const std::string& nonce_b64,
		const std::array<unsigned char, crypto_secretbox_KEYBYTES>& key);

	bool add_password(const char* username, const char* label, const char* password);
	std::vector<std::pair<std::string, std::string>> get_passwords(const char* username);
};

#endif
