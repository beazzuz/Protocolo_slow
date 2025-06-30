CXX      = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -O2 -pedantic

slowclient: peripheral.cpp session.hpp
	$(CXX) $(CXXFLAGS) $^ -o $@

clean:
	rm -f slowclient
