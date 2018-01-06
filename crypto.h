#ifndef CRYPTO_H
#define CRYPTO_H

#include <exception>
#include <vector>
#include <array>
#include <string>

#include <openssl/evp.h>

namespace crypto{
	const int BLOCK_SIZE = 256;

	class exception : public std::exception{
	public:
		exception(const std::string &msg):message(msg){}
		virtual const char *what()const noexcept{
			return message.c_str();
		}

	private:
		const std::string message;
	};

	class encrypt_stream{
	public:
		encrypt_stream(const std::string&);
		~encrypt_stream();

		int encrypt(const unsigned char*, int, unsigned char*, int);
		int finalize(unsigned char*, int);

	private:
		EVP_CIPHER_CTX *ctx;
		unsigned char key[32];
		unsigned char iv[16];
	};

	class decrypt_stream{
	public:
		decrypt_stream(const std::string&);
		~decrypt_stream();

		int decrypt(const unsigned char*, int, unsigned char*, int);
		int finalize(unsigned char*, int);

	private:
		EVP_CIPHER_CTX *ctx;
		unsigned char key[32];
		unsigned char iv[16];
	};

	// "one-and-done" functions
	void encrypt(const std::string&, const std::vector<unsigned char>&, std::vector<unsigned char>&);
	void decrypt(const std::string&, const std::vector<unsigned char>&, std::vector<unsigned char>&);
}

#endif // CRYPTO_H
