SOURCES := main.cpp crypto.cpp
OUTPUT := scrambler

all:
	g++ -o $(OUTPUT) -Wall -pedantic -std=c++17 -g $(SOURCES) -lcrypto

release:
	g++ -o $(OUTPUT) -Wall -pedantic -std=c++17 -O2 $(SOURCES) -s -lcrypto
