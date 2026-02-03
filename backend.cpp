
#include "sodium_init.h"
#include "imgui.h"
#include "json.hpp"

#include <string>
#include <fstream>
#include <sodium.h>
#include "backend.h"
//encode:
std::string Backend::base64_encode(const unsigned char* data, size_t len) {
	size_t out_len =
		sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL);

	std::string out(out_len, '\0');

	sodium_bin2base64(
		out.data(),
		out.size(),
		data,
		len,
		sodium_base64_VARIANT_ORIGINAL);

	// махаме trailing '\0'
	out.resize(strlen(out.c_str()));
	return out;
}
//decode:
std::vector<unsigned char> Backend::base64_decode(const std::string& b64) {
	std::vector<unsigned char> bin(b64.size());
	size_t bin_len = 0;

	if (sodium_base642bin(
		bin.data(),
		bin.size(),
		b64.c_str(),
		b64.size(),
		nullptr,
		&bin_len,
		nullptr,
		sodium_base64_VARIANT_ORIGINAL) != 0) {
		throw std::runtime_error("Invalid base64");
	}

	bin.resize(bin_len);
	return bin;
}
//function that hash user's password:
std::string Backend::hash_password(const char* password) {
	char hashed_password[crypto_pwhash_STRBYTES];
	if (crypto_pwhash_str(hashed_password,
		password,
		strlen(password),
		crypto_pwhash_OPSLIMIT_INTERACTIVE,
		crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
		IM_ASSERT(false && "Hash faileed");
		std::abort();
	}
	return std::string(hashed_password);
}
//Encrypt key:
std::array<unsigned char, crypto_secretbox_KEYBYTES>
Backend::derive_key(const std::string& password, const unsigned char* salt)
{
	std::array<unsigned char, crypto_secretbox_KEYBYTES> key;

	crypto_pwhash(
		key.data(),
		key.size(),
		password.c_str(),
		password.size(),
		salt,
		crypto_pwhash_OPSLIMIT_INTERACTIVE,
		crypto_pwhash_MEMLIMIT_INTERACTIVE,
		crypto_pwhash_ALG_DEFAULT);

	return key;
}
bool Backend::verify(const char* password, std::string hashed) {
	return crypto_pwhash_str_verify(hashed.c_str(), password, strlen(password)) == 0;
}
//TODO: function for encrypting the unique key

//function for login user and register users:
bool Backend::log_in(const char* name, const char* password) {
	std::string hashed;
	std::ifstream inFile("user_data.json");
	if (inFile.is_open()) {
		inFile >> database;
		inFile.close();
	}
	else {
		database["users"] = json::array();
	}
	for (auto& user : database["users"]) {
		if (name == user["username"]) {
			hashed = user["password"].get<std::string>();
		}
	}
	if (hashed.empty()) {
		return false;  //user not found
	}
	return verify(password, hashed); // if user found: verify password
}
bool Backend::registration(const char* name, const char* password, const char* key) {
	std::ifstream inFile("user_data.json");
	if (inFile.is_open()) {
		inFile >> database;
		inFile.close();
	}
	else {
		database["users"] = json::array();
	}
	//verify username
	for (const auto& user : database["users"]) {
		if (name == user["username"]) {
			return false;
		}
	}
	unsigned char key_salt[crypto_pwhash_SALTBYTES];
	randombytes_buf(key_salt, sizeof key_salt);
	database["users"].push_back({
		{"username",name},
		{"password",hash_password(password)},
		{"key_hash",hash_password(key)},
		{"key_salt", base64_encode(key_salt, crypto_pwhash_SALTBYTES)},
		{"passwords",json::array()}
		});
	std::ofstream outFile("user_data.json");
	if (outFile.is_open()) {
		outFile << database.dump(4);
		outFile.close();
	}
	else {
		IM_ASSERT(false && "file can't be opened");
		std::abort();
	}
	return true;
}
bool Backend::unlock_vault(const char* username, const char* input_key) {

	std::ifstream inFile("user_data.json");
	if (inFile.is_open()) {
		inFile >> database;
		inFile.close();
	}
	else {
		database["users"] = json::array();
	}

	for (auto& user : database["users"]) {

		if (user["username"] != username) {
			continue;
		}

		if (!verify(input_key, user["key_hash"])) {
			return false;
		}

		auto salt = base64_decode(user["key_salt"]);
		if (salt.size() != crypto_pwhash_SALTBYTES) {
			IM_ASSERT(false && "Invalid salt size");
			std::abort();
		}

		current_session_key = derive_key(input_key, salt.data());
		return true;
	}
	return false;
}
//encrypt password:
std::string Backend::encrypt_password(
	const std::string& plaintext,
	const std::array<unsigned char, crypto_secretbox_KEYBYTES>& key,
	std::string& out_nonce_b64) {
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	randombytes_buf(nonce, sizeof nonce);

	std::vector<unsigned char> cipher(
		plaintext.size() + crypto_secretbox_MACBYTES);

	crypto_secretbox_easy(
		cipher.data(),
		reinterpret_cast<const unsigned char*>(plaintext.data()),
		plaintext.size(),
		nonce,
		key.data());

	out_nonce_b64 = base64_encode(nonce, sizeof nonce);
	return base64_encode(cipher.data(), cipher.size());
}
//decrypt password:
std::string Backend::decrypt_password(
	const std::string& cipher_b64,
	const std::string& nonce_b64,
	const std::array<unsigned char, crypto_secretbox_KEYBYTES>& key) {
	auto cipher = base64_decode(cipher_b64);
	auto nonce = base64_decode(nonce_b64);

	std::vector<unsigned char> plain(cipher.size() - crypto_secretbox_MACBYTES);

	if (crypto_secretbox_open_easy(
		plain.data(),
		cipher.data(),
		cipher.size(),
		nonce.data(),
		key.data()) != 0) {
		throw std::runtime_error("Decrypt failed");
	}

	return std::string(plain.begin(), plain.end());
}
//add encrypted password to .json:
bool Backend::add_password(const char* username, const char* label, const char* password) {
	// проверка дали имаме unlock-нат vault
	if (current_session_key.empty()) {
		IM_ASSERT(false&&"Vault is not unlocked");
		std::abort();
	}

	for (auto& user : database["users"]) {
		if (user["username"] != username)
			continue;

		// 1️⃣ Encrypt the password
		std::string nonce_b64;
		std::string cipher_b64 = encrypt_password(password, current_session_key, nonce_b64);

		// 2️⃣ Add encrypted password to the user's passwords array
		user["passwords"].push_back({
			{"label", label},
			{"cipher", cipher_b64},
			{"nonce", nonce_b64} });

		// 3️⃣ Save JSON database
		std::ofstream outFile("user_data.json");
		if (!outFile.is_open()) {
			throw std::runtime_error("Could not open database file");
		}
		outFile << database.dump(4);
		outFile.close();

		return true; // successfully added
	}
	return false; // user not found
}

std::vector<std::pair<std::string, std::string>> Backend::get_passwords(const char* username) {

	if (current_session_key.empty()) {
		IM_ASSERT(false && "Vault is not unlocked");
		std::abort();
	}

	std::vector<std::pair<std::string, std::string>> result;

	for (auto& user : database["users"]) {
		if (user["username"] != username)
			continue;

		for (auto& pw : user["passwords"]) {
			std::string label = pw["label"];
			std::string cipher = pw["cipher"];
			std::string nonce = pw["nonce"];

			try {
				std::string decrypted = decrypt_password(cipher, nonce, current_session_key);
				result.push_back({ label, decrypted });
			}
			catch (const std::exception& e) {
				IM_ASSERT(false && "Failed to decrypt password");
				std::abort();
			}
		}
		break;
	}
	return result;
}