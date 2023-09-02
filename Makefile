# CXX=x86_64-w64-mingw32-gcc
CXX=gcc
CXXFLAGS=-Wall -Wextra -pedantic
LDFLAGS=-lm -lz
TARGET=rvld

$(TARGET): src/main.c src/rvl.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) src/main.c -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: clean
