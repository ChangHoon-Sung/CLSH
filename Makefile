CC = gcc
CFLAGS = -W -Wall -fstack-protector-all -Wstack-protector
DBGFLAGS = -fsanitize=address -fno-optimize-sibling-calls -fno-omit-frame-pointer
TARGET = clsh

all : $(TARGET)

install : $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin

clsh : clsh.c
	$(CC) $(CFLAGS) -O2 -o $@ $^

debug : clsh.c
		$(CC) $(CFLAGS) $(DBGFLAGS) -g -Og -o $@.out $^ -DDEBUG

clean :
	rm -rf $(TARGET) *.out