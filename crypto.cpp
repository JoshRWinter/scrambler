#include <array>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <string.h>

#include "crypto.h"

#define DEBUG(x) (std::string("[ ") + __FILE__ + ": " + __func__ + ": " + std::to_string(__LINE__) + "] " + x)

// back-end encrypt & decrypt functions
static void scramble(const std::vector<unsigned char>&, const std::array<unsigned char, 32>&, const std::array<unsigned char, 16>&, std::vector<unsigned char>&);
static void unscramble(const std::vector<unsigned char>&, const std::array<unsigned char, 32>&, const std::array<unsigned char, 16>&, std::vector<unsigned char>&);

// turn passphrase into raw key
static void stretch(const std::string &pass, std::array<unsigned char, 32> &bytes, std::array<unsigned char, 16> &iv){
	const int ret = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, (unsigned char*)pass.c_str(), pass.length(), 1, &bytes[0], &iv[0]);
	if(ret == 0)
		throw crypto::exception("Could not stretch the key");
}

// encryption interface
void crypto::encrypt(const std::string &password, const std::vector<unsigned char> &plaintext, std::vector<unsigned char> &ciphertext){
	std::array<unsigned char, 32> key;
	std::array<unsigned char, 16> iv; // init vector
	memset(&key[0], 0, key.size());
	memset(&iv[0], 0, iv.size());

	// compute the key and iv
	stretch(password, key, iv);

	ciphertext.resize(plaintext.size() + 256);
	scramble(plaintext, key, iv, ciphertext);
}

// decryption interface
void crypto::decrypt(const std::string &password, const std::vector<unsigned char> &ciphertext, std::vector<unsigned char> &plaintext){
	std::array<unsigned char, 32> key;
	std::array<unsigned char, 16> iv; // init vector
	memset(&key[0], 0, key.size());
	memset(&iv[0], 0, iv.size());

	// compute key and iv
	stretch(password, key, iv);

	plaintext.resize(ciphertext.size());
	unscramble(ciphertext, key, iv, plaintext);
}

void scramble(const std::vector<unsigned char> &plaintext, const std::array<unsigned char, 32> &key, const std::array<unsigned char, 16> &iv, std::vector<unsigned char> &ciphertext){
	EVP_CIPHER_CTX *ctx;
	std::string err;
	int cipherlen = 0;
	int len;

	// construct the context
	if(!(ctx = EVP_CIPHER_CTX_new())){
		err = DEBUG("couldn't construct evp cipher context");
		goto error;
	}

	// init the encryption operation
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, &key[0], &iv[0])){
		err = DEBUG("couldn't init evp cipher operation");
		goto error;
	}

	// encryption block loop
	for(std::vector<unsigned char>::size_type i = 0; i < plaintext.size(); i += 256){
		if(1 != EVP_EncryptUpdate(ctx, &ciphertext[i], &len, &plaintext[i], plaintext.size() - i)){
			err = DEBUG("couldn't encrypt " + std::to_string(i) + " block");
			goto error;
		}

		cipherlen += len;
	}

	// finalize the encryption operation
	if(1 != EVP_EncryptFinal_ex(ctx, &ciphertext[cipherlen], &len)){
		err = DEBUG("couldn't finalize the encryption operation");
		goto error;
	}
	cipherlen += len;
	ciphertext.resize(cipherlen);

	// finalize the evp context
	EVP_CIPHER_CTX_free(ctx);
	return;

error:
	EVP_CIPHER_CTX_free(ctx);
	throw crypto::exception(err);
}

void unscramble(const std::vector<unsigned char> &ciphertext, const std::array<unsigned char, 32> &key, const std::array<unsigned char, 16> &iv, std::vector<unsigned char> &plaintext){
	EVP_CIPHER_CTX *ctx;
	int plainlen = 0;
	int len;
	std::string err;

	// construct evp context
	if(!(ctx = EVP_CIPHER_CTX_new())){
		err = DEBUG("couldn't construct evp cipher context");
		goto error;
	}

	// init the encryption operation
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, &key[0], &iv[0])){
		err = DEBUG("couldn't init evp cipher operation");
		goto error;
	}

	// decryption block loop
	for(std::vector<unsigned char>::size_type i = 0; i < ciphertext.size(); i += 256){
		if(1 != EVP_DecryptUpdate(ctx, &plaintext[i], &len, &ciphertext[i], ciphertext.size() - i)){
			err = DEBUG("couldn't decrypt " + std::to_string(i) + " block");
			goto error;
		}

		plainlen += len;
	}

	// finalize the decryption operation
	if(1 != EVP_DecryptFinal_ex(ctx, &plaintext[plainlen], &len)){
		err = DEBUG("couldn't finalize the decryption operation");
		goto error;
	}
	plainlen += len;
	plaintext.resize(plainlen);

	// finalize the evp context
	EVP_CIPHER_CTX_free(ctx);
	return;

error:
	EVP_CIPHER_CTX_free(ctx);
	throw crypto::exception(err);
}
