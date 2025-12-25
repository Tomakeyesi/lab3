CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -pedantic
LDFLAGS = -lUnitTest++

TARGET = test_route
SOURCES = main.cpp modAlphaCipher.cpp
OBJECTS = $(SOURCES:.cpp=.o)

UNIT_TEST_INC = /usr/include/UnitTest++
UNIT_TEST_LIB = /usr/lib/x86_64-linux-gnu

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

test: $(TARGET)
	./$(TARGET)
	
run: clean test

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all test clean run help
