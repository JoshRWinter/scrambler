SOURCES := main.cpp crypto.cpp

all:
	g++ -o scramble -std=c++17 -g $(SOURCES) -lcrypto

release:
	g++ -o scramble -std=c++17 -O2 $(SOURCES) -s -lcrypto
