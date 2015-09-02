CC=g++ -std=c++11
CFLAGS=-c -Wall 
LDFLAGS=
SOURCES=s_des.cpp encryptor_decryptor.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=s_des

all: $(EXECUTABLE)
    
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o  $@ -g 

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@
