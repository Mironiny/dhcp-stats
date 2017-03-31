CFLAGS=-Wall -Wextra -pedantic -std=c++11

all: dhcp-stats.cpp
	g++ $(CFLAGS) dhcp-stats.cpp -o dhcp-stats -pthread -lncurses