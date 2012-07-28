#!/usr/bin/make -f
# required packages:
#  * mingw32 for compiling
#  * wine for running

CC    = i586-mingw32msvc-gcc
CXX   = i586-mingw32msvc-g++
FLAGS = -Wno-deprecated -lws2_32 -Wall -Wextra

SRC=tcp_server.c getaddrinfo.c
BIN=tcp_server getaddrinfo

demo: $(SRC)
	$(foreach app, $(BIN), $(CXX) $(app).c -o $(app).exe $(FLAGS);)

server-test: server test

server: tcp_server.c
	${CXX} -o $@.exe $< ${FLAGS}

test: server
	wine $<.exe

clean:
	@-rm -rf *.exe

.PHONY: all clean

