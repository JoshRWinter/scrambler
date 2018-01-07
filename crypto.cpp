#include <openssl/aes.h>
#include <openssl/err.h>
#include <string.h>

#include "crypto.h"

#define DEBUG(x) (std::string("[") + __FILE__ + ": " + __func__ + ": " + std::to_string(__LINE__) + "] " + x)

// turn passphrase into raw key
static void stretch(const std::string &pass, unsigned char *key, unsigned char *iv){
	const int ret = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, (unsigned char*)pass.c_str(), pass.length(), 1, key, iv);
	if(ret == 0)
		throw crypto::exception("Could not stretch the key");
}

//
// encrypt stream object
//
crypto::encrypt_stream::encrypt_stream(const std::string &pw){
	// initialize the key and iv
	stretch(pw, key, iv);

	// construct the evp cipher context
	if(!(ctx = EVP_CIPHER_CTX_new()))
		throw crypto::exception(DEBUG("couldn't construct evp cipher context"));

	// initialize encryption operation
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		throw crypto::exception(DEBUG("couldn't initialize the encryption operation"));
}

crypto::encrypt_stream::~encrypt_stream(){
	EVP_CIPHER_CTX_free(ctx);
}

int crypto::encrypt_stream::encrypt(const unsigned char *plaintext, int plainlen, unsigned char *ciphertext, int cipherlen){
	if(cipherlen < plainlen + BLOCK_SIZE - 1)
		throw crypto::exception(DEBUG("the size of the ciphertext buffer must be at least (plainlen + BLOCK_SIZE - 1). BLOCKSIZE = 256"));

	int written;
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &written, plaintext, plainlen))
		throw crypto::exception(DEBUG("failed to encrypt block"));

	return written;
}

int crypto::encrypt_stream::finalize(unsigned char *ciphertext, int cipherlen){
	if(cipherlen < BLOCK_SIZE)
		throw crypto::exception(DEBUG("cipherlen should be at least BLOCK_SIZE. BLOCK_SIZE = 256"));

	int written;
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext, &written))
		throw crypto::exception(DEBUG("could not finalize the encryption operation"));

	return written;
}

//
// decrypt stream object
//
crypto::decrypt_stream::decrypt_stream(const std::string &pw){
	// init key and iv
	stretch(pw, key, iv);

	// construct evp cipher context
	if(!(ctx = EVP_CIPHER_CTX_new()))
		throw crypto::exception(DEBUG("could not construct evp cipher context"));

	// initialize decryption operation
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		throw crypto::exception(DEBUG("could not initialize the decryption operation"));
}

crypto::decrypt_stream::~decrypt_stream(){
	EVP_CIPHER_CTX_free(ctx);
}

int crypto::decrypt_stream::decrypt(const unsigned char *ciphertext, int cipherlen, unsigned char *plaintext, int plainlen){
	if(plainlen < cipherlen + BLOCK_SIZE)
		throw crypto::exception(DEBUG("the size of the plaintext buffer should be at least (cipherlen + BLOCKSIZE). BLOCKSIZE = 256"));

	int written;
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &written, ciphertext, cipherlen))
		throw crypto::exception(DEBUG("failed to decrypt block"));

	return written;
}

int crypto::decrypt_stream::finalize(unsigned char *plaintext, int plainlen){
	if(plainlen < BLOCK_SIZE)
		throw crypto::exception(DEBUG("plainlen should be at least BLOCK_SIZE. BLOCK_SIZE = 256"));

	int written;
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext, &written))
		throw crypto::exception(DEBUG("incorrect padding format"));

	return written;
}

//
// one and done functions (full in memory encryption)
//
void crypto::encrypt(const std::string &passwd, const std::vector<unsigned char> &plaintext, std::vector<unsigned char> &ciphertext){
	crypto::encrypt_stream encrypt(passwd);

	ciphertext.resize(plaintext.size() + BLOCK_SIZE - 1);

	const int written1 = encrypt.encrypt(plaintext.data(), plaintext.size(), ciphertext.data(), ciphertext.size());
	ciphertext.resize(written1 + BLOCK_SIZE);
	const int written2 = encrypt.finalize(ciphertext.data() + written1, ciphertext.size() - written1);
	ciphertext.resize(written1 + written2);
}

void crypto::decrypt(const std::string &passwd, const std::vector<unsigned char> &ciphertext, std::vector<unsigned char> &plaintext){
	crypto::decrypt_stream decrypt(passwd);

	plaintext.resize(ciphertext.size() + BLOCK_SIZE);

	const int written1 = decrypt.decrypt(ciphertext.data(), ciphertext.size(), plaintext.data(), plaintext.size());
	plaintext.resize(written1 + BLOCK_SIZE);
	const int written2 = decrypt.finalize(plaintext.data() + written1, plaintext.size() - written1);
	plaintext.resize(written1 + written2);
}
