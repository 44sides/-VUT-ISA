CC = g++
CFLAGS  = -Wall -pedantic -Wextra
TARGET = secret
LIBS = -lpcap -lcrypto -lssl
 
all: $(TARGET)
 
$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) $(TARGET).cpp -o $(TARGET) $(LIBS)