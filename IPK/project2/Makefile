
# Project - IPK 2021, Packet Sniffer
# Author - Lukas Foltyn
# Makefile

# compiler
CPP=g++

# flags
CPPFLAGS= -std=c++17 -Wall -Werror -pedantic -g

# executable
executable=ipk-sniffer

# object files
obj_files = $(patsubst %.cpp, %.o, $(wildcard *.cpp))

.PHONY: build clean

build:${executable}

${executable}:${obj_files}
	${CPP} $^ -lpcap -o $@

%.o:%.cpp %.h
	${CPP} ${CPPFLAGS} -c $<

# removes the executable file and the object files
# no errors are thrown
clean:
	@rm ${obj_files} ${executable} 2>/dev/null || true


