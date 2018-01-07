#include <iostream>
#include <fstream>
#include <vector>
#include <exception>

#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#endif

#include "crypto.h"

#define HEADER_LENGTH (strlen(MAGIC_STRING) + sizeof(unsigned long long))
#define MAGIC_STRING "SCRAMBLED"
#define CHUNK_SIZE 4096
#define MAX_CHECKSUMMED 5010

enum class task{
	lock,
	unlock
};

class scrambler_exception : public std::exception{
public:
	scrambler_exception(const std::string &msg)
		:message(msg){}
	virtual const char *what()const noexcept{
		return message.c_str();
	}
private:
	const std::string message;
};

static void help();

static std::string getpassword();
static unsigned long long checksum(const unsigned char*, unsigned);
static void encrypt(const std::string&);
static void decrypt(const std::string&);

static int read(std::ifstream&, std::vector<unsigned char>&);
static void write(std::ofstream&, const std::vector<unsigned char>&);
static long long filesize(const std::string&);

int main(int argc, char **argv){
	if(argc != 3){
		help();
		return 1;
	}

	const std::string operation = argv[1];
	const std::string filename = argv[2];

	// figure out whether to lock or unlock the file
	task action;
	if(operation == "lock")
		action = task::lock;
	else if(operation == "unlock")
		action = task::unlock;
	else{
		help();
		return 1;
	}

	try{
		if(action == task::lock)
			encrypt(filename);
		else if(action == task::unlock)
			decrypt(filename);
	}catch(const std::exception &e){
		std::cerr << "error: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}

// help text
void help(){
	std::cout << "help" << std::endl;
}

void encrypt(const std::string &fname){
	// test to see if output file already exists
	{
		std::ifstream test(fname + ".lock");
		if(!!test)
			throw scrambler_exception("could not write to file \"" + fname + ".lock\", file already exists");
	}

	// see if file is already locked
	if(fname.rfind(".lock") == fname.size() - 5)
		throw scrambler_exception("file \"" + fname + "\" is already locked!");

	// file streams
	std::ifstream in(fname, std::ifstream::binary);
	if(!in)
		throw scrambler_exception("could not open file \"" + fname + "\" in read mode");
	const long long filelen = filesize(fname);
	std::ofstream out(fname + ".lock", std::ifstream::binary);
	if(!out)
		throw scrambler_exception("could not open file \"" + fname + ".lock\" in write mode");

	// write the header to the output file
	const std::vector<unsigned char> header = {'S', 'C', 'R', 'A', 'M', 'B', 'L', 'E', 'D'};
	write(out, header);
	// write checksum placeholder
	const unsigned long long placeholder = 0;
	out.write((char*)&placeholder, sizeof(unsigned long long));

	// data buffers
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	plaintext.resize(CHUNK_SIZE);

	// get the password
	std::cout << "enter password: " << std::flush;
	const std::string passwd = getpassword();
	std::cout << "confirm password: " << std::flush;
	if(getpassword() != passwd)
		throw scrambler_exception("passwords do not match");

	// encryption stream object
	crypto::encrypt_stream stream(passwd);

	int written = 0;
	unsigned long long plaintext_checksum = 0;
	int checksummed = 0;
	long long bytesread = 0;
	while(plaintext.size() == CHUNK_SIZE){
		// read a chunk
		const int got = read(in, plaintext);
		plaintext.resize(got);
		bytesread += got;

		// update the plaintext checksum
		if(checksummed < MAX_CHECKSUMMED){
			int checksumming = plaintext.size();
			if(checksummed + checksumming > MAX_CHECKSUMMED)
				checksumming -= (checksummed + checksumming) - MAX_CHECKSUMMED;

			plaintext_checksum += checksum(plaintext.data(), checksumming);
			checksummed += checksumming;
		}

		// encrypt it
		ciphertext.resize(plaintext.size() + crypto::BLOCK_SIZE - 1);
		written = stream.encrypt(plaintext.data(), plaintext.size(), ciphertext.data(), ciphertext.size());
		ciphertext.resize(written);

		// write it
		write(out, ciphertext);

		// status message
		if(filelen > 5'000'000){
			const int percent = ((float)bytesread / filelen) * 100;
			std::cout << "  " << percent << "%\r" << std::flush;
		}
	}

	if(filelen > 5'000'000)
		std::cout << "  100%" << std::endl;

	// finalize the operation
	ciphertext.resize(crypto::BLOCK_SIZE);
	written = stream.finalize(ciphertext.data(), ciphertext.size());
	ciphertext.resize(written);
	write(out, ciphertext);

	// write the plaintext checksum
	out.seekp(9);
	out.write((char*)&plaintext_checksum, sizeof(plaintext_checksum));

	// remove the original file
	remove(fname.c_str());
}

void decrypt(const std::string &fname){
	// test if file has correct name format
	const unsigned index = fname.rfind(".lock");
	const std::string output_fname = fname.substr(0, fname.size() - 5);
	if(index != fname.length() - 5)
		throw scrambler_exception("file \"" + fname + "\" does not have the correct name format");

	// test to see if the output file already exists
	{
		std::ifstream test(output_fname);
		if(!!test)
			throw scrambler_exception("could not write to file \"" + output_fname + "\", file already exists!");
	}

	// input file stream
	std::ifstream in(fname, std::ifstream::binary);
	if(!in)
		throw scrambler_exception("could not open file \"" + fname + "\" in read mode");
	const long long filelen = filesize(fname);

	// read the header
	char header[10] = "xxxxxxxxx";
	in.read(header, 9);
	header[9] = 0;
	if(strcmp("SCRAMBLED", header))
		throw scrambler_exception("file \"" + fname + "\" is not a locked file.");

	// read the plaintext checksum
	unsigned long long plaintext_checksum;
	in.read((char*)&plaintext_checksum, sizeof(plaintext_checksum));

	// get the password
	std::cout << "enter password: " << std::flush;
	const std::string passwd = getpassword();

	// output file stream
	std::ofstream out(output_fname, std::ifstream::binary);
	if(!out)
		throw scrambler_exception("could not open file \"" + output_fname + "\" in write mode");

	// data buffers
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	ciphertext.resize(CHUNK_SIZE);

	// decryption stream
	crypto::decrypt_stream stream(passwd);

	unsigned long long confirm_checksum = 0;
	int written = 0;
	int checksummed = 0;
	long long bytesread = 0;
	while(ciphertext.size() == CHUNK_SIZE){
		const int got = read(in, ciphertext);
		ciphertext.resize(got);
		bytesread += got;

		// decrypt
		plaintext.resize(ciphertext.size() + crypto::BLOCK_SIZE);
		written = stream.decrypt(ciphertext.data(), ciphertext.size(), plaintext.data(), plaintext.size());
		plaintext.resize(written);

		// update the confirmation checksum
		if(checksummed < MAX_CHECKSUMMED){
			int checksumming = plaintext.size();
			if(checksummed + checksumming > MAX_CHECKSUMMED)
				checksumming -= (checksummed + checksumming) - MAX_CHECKSUMMED;

			confirm_checksum += checksum(plaintext.data(), checksumming);
			checksummed += checksumming;
		}
		else if(confirm_checksum != plaintext_checksum){
			out.close();
			remove(output_fname.c_str());
			throw scrambler_exception("incorrect password (checksum failure)");
		}

		// write
		write(out, plaintext);

		if(filelen > 5'000'000){
			const int percent = ((double)bytesread / filelen) * 100;
			std::cout << "  " << percent << "%\r" << std::flush;
		}
	}

	if(filelen > 5'000'000)
		std::cout << "  100%" << std::endl;

	plaintext.resize(crypto::BLOCK_SIZE);
	try{
		written = stream.finalize(plaintext.data(), plaintext.size());
	}catch(const crypto::exception &e){
		out.close();
		remove(output_fname.c_str());
		throw scrambler_exception("incorrect password (format error)");
	}
	plaintext.resize(written);

	// update the confirmation checksum
	if(checksummed < MAX_CHECKSUMMED){
		int checksumming = plaintext.size();
		if(checksummed + checksumming > MAX_CHECKSUMMED)
			checksumming -= (checksummed + checksumming) - MAX_CHECKSUMMED;

		confirm_checksum += checksum(plaintext.data(), checksumming);
		checksummed += checksumming;
	}

	if(confirm_checksum != plaintext_checksum){
		out.close();
		remove(output_fname.c_str());
		throw scrambler_exception("incorrect password (checksum failure)");
	}

	write(out, plaintext);
}

// return file contents
int read(std::ifstream &in, std::vector<unsigned char> &contents){
	const int attempt = contents.size();

	in.read((char*)contents.data(), attempt);

	const int got = in.gcount();

	return got;
}

// write file data
void write(std::ofstream &out, const std::vector<unsigned char> &contents){
	const int attempt = contents.size();

	out.write((char*)contents.data(), attempt);
}

long long filesize(const std::string &fname){
#ifdef _WIN32
	throw scrambler_exception("not implemented filesize");
#else
	struct stat buff;
	stat(fname.c_str(), &buff);
	return buff.st_size;
#endif // _WIN32
}

// get password
std::string getpassword(){
#ifdef _WIN32
	throw scrambler_exception("unimplemented password");
#else
	termios term;
	tcgetattr(1, &term);
	term.c_lflag &= ~ECHO;
	tcsetattr(1, TCSANOW, &term);

	std::string passwd;
	for(;;){
		const char c = fgetc(stdin);

		if(c == '\n') // newline
			break;
		else if(c == '\b'){ // backspace
			if(passwd.size() > 0)
				passwd.erase(passwd.end() - 1);
		}
		else // regular char
			passwd.push_back(c);
	}

	term.c_lflag |= ECHO;
	tcsetattr(1, TCSANOW, &term);

	std::cout << std::endl;

	return passwd;
#endif // _WIN32
}

// produce checksum given 'raw'
unsigned long long checksum(const unsigned char *data, unsigned size){
	unsigned long long sum = 0;

	for(unsigned i = 0; i < size; ++i){
		if(data[i] > 100 && data[i] < 120)
			sum += data[i] / 1.5;
		else if(data[i] >= 120 && data[i] < 130)
			sum += data[i] * 1.8;
		else
			sum += data[i];
	}

	return sum;
}
