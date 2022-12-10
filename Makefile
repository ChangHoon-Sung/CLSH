CC = gcc
CFLAGS = -W -Wall -fstack-protector-all -Wstack-protector -fsanitize=address -fno-optimize-sibling-calls -fno-omit-frame-pointer
TARGET = clsh

all : $(TARGET)
	$(CC) $(CFLAGS) -o $@.out $^

clsh : clsh.c
	$(CC) $(CFLAGS) -O2 -o $@.out $^

debug : clsh.c
		$(CC) $(CFLAGS) -g -Og -o $@.out $^ -DDEBUG

clean :
	rm -f $(TARGET)