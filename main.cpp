#include <iostream>
#include <fstream>
#include <vector>
#include <exception>

#include <string.h>
#include <unistd.h>

#include "crypto.h"

#define HEADER_LENGTH (strlen(MAGIC_STRING) + sizeof(unsigned long long))
#define MAGIC_STRING "SCRAMBLED"

enum class task{
	lock,
	unlock
};

class scrambler_exception : std::exception{
public:
	scrambler_exception(const std::string &msg)
		:message(msg){}
	virtual const char *what()const noexcept{
		return message.c_str();
	}
private:
	const std::string message;
};

static int run(const std::string&, const std::string&);
static void help();

static bool scrambled(const std::vector<unsigned char>&);
static unsigned long long checksum(const std::vector<unsigned char>&);
static void encrypt(const std::string&, const std::vector<unsigned char>&, std::vector<unsigned char>&);
static void decrypt(const std::string&, const std::vector<unsigned char>&, std::vector<unsigned char>&);

static void read(const std::string&, std::vector<unsigned char>&);
static void write(const std::string&, std::vector<unsigned char>&);

int main(int argc, char **argv){
	if(argc != 3){
		help();
		return 1;
	}

	const std::string operation = argv[1];
	const std::string filename = argv[2];

	try{
		const int ret = run(operation, filename);
		return ret;
	}catch(const scrambler_exception &e){
		std::cout << "error: " << e.what() << std::endl;
	}

	return 1;
}

// the main logic
int run(const std::string &operation, const std::string &filename){
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

	// read the input file
	std::vector<unsigned char> input;
	read(filename, input);

	const bool locked = scrambled(input);
	if(action == task::lock && locked){
		std::cout << "this file is already locked" << std::endl;
		return 1;
	}
	else if(action == task::unlock && !locked){
		std::cout << "this file is either corrupted or not locked" << std::endl;
		return 1;
	}

	// get the password
	const std::string password = getpass("enter password: ");
	if(action == task::lock){
		const std::string confirm = getpass("confirm password: ");
		if(confirm != password){
			std::cout << "passwords do not match!" << std::endl;
			return 1;
		}
	}

	// encrypt or decrypt
	std::vector<unsigned char> translated;
	std::string outname; // output file name
	if(action == task::lock){
		encrypt(password, input, translated);

		// write the result
		write(filename + ".lock", translated);
		remove(filename.c_str());
	}
	else if(action == task::unlock){
		decrypt(password, input, translated);

		// write the result
		write(filename.substr(0, filename.size() - 5), translated);
	}

	return 0;
}

// help text
void help(){
	std::cout << "help" << std::endl;
}

// determin if file is already scrambled
bool scrambled(const std::vector<unsigned char> &r){
	std::vector<unsigned char> raw = r;

	if(raw.size() < HEADER_LENGTH)
		return false;

	// magic check
	if(raw.at(0) != 'S' || raw.at(1) != 'C' || raw.at(2) != 'R' ||
		raw.at(3) != 'A' || raw.at(4) != 'M' || raw.at(5) != 'B' ||
		raw.at(6) != 'L' || raw.at(7) != 'E' || raw.at(8) != 'D')
		return false;

	// checksum check
	unsigned long long chksum;
	memcpy(&chksum, &raw.at(9), sizeof(unsigned long long));
	raw.erase(raw.begin(), raw.begin() + HEADER_LENGTH); // erase the header
	if(chksum != checksum(raw))
		return false;

	return true;
}

// produce checksum given 'raw'
unsigned long long checksum(const std::vector<unsigned char> &raw){
	unsigned long long sum = 0;

	for(unsigned i = HEADER_LENGTH; i < raw.size(); ++i)
		sum += raw[i];

	return sum;
}

// encrypt a file and compute the header
void encrypt(const std::string &passwd, const std::vector<unsigned char> &plaintext, std::vector<unsigned char> &ciphertext){
	std::vector<unsigned char> header;
	header.reserve(HEADER_LENGTH);

	// encrypt
	crypto::encrypt(passwd, plaintext, ciphertext);

	// write magic
	header.push_back('S'); header.push_back('C'); header.push_back('R');
	header.push_back('A'); header.push_back('M'); header.push_back('B');
	header.push_back('L'); header.push_back('E'); header.push_back('D');

	// write checksum
	const unsigned long long check = checksum(ciphertext);
	const unsigned char *const check_char = (const unsigned char*)&check;
	for(unsigned i = 0; i < sizeof(check); ++i)
		header.push_back(check_char[i]);

	// insert the header to the beginning of ciphertext
	ciphertext.insert(ciphertext.begin(), header.begin(), header.end());
}

void decrypt(const std::string &passwd, const std::vector<unsigned char> &cipher, std::vector<unsigned char> &plaintext){
	std::vector<unsigned char> ciphertext = cipher;
	try{
		// erase the header
		ciphertext.erase(ciphertext.begin(), ciphertext.begin() + HEADER_LENGTH);

		// decrypt
		crypto::decrypt(passwd, ciphertext, plaintext);
	}catch(const crypto::exception &e){
		throw scrambler_exception(std::string("decryption error: ") + e.what());
	}
}

// return file contents
void read(const std::string &fname, std::vector<unsigned char> &contents){
	// open the file
	std::ifstream in(fname);
	if(!in)
		throw scrambler_exception("file \"" + fname + "\" does not exist.");

	// read the file
	const int CHUNK = 2048;
	int place = 0;
	while(!in.eof()){
		contents.resize(contents.size() + CHUNK);
		in.read((char*)&contents.at(place), CHUNK);
		place += in.gcount();
	}
	contents.resize(place);
}

// write file data
void write(const std::string &fname, std::vector<unsigned char> &contents){
	{
		// check to see if the file already exists
		std::ifstream test(fname);
		if(!!test)
			throw scrambler_exception("could not create file \"" + fname + "\", that file already exists!");
	}
	// open file
	std::ofstream out(fname);
	if(!out)
		throw scrambler_exception("could not open \"" + fname + "\" in write mode");

	out.write((char*)&contents[0], contents.size());
}
