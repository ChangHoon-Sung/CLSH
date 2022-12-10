CC = gcc
CFLAGS = -W -Wall -fstack-protector-all -Wstack-protector -fsanitize=address -fno-optimize-sibling-calls -fno-omit-frame-pointer -O1 -g
TARGET = clsh

all : $(TARGET)
	$(CC) $(CFLAGS) -o $@.out $^

clsh : clsh.c
	$(CC) $(CFLAGS) -o $@.out $^

debug : clsh.c
		$(CC) $(CFLAGS) -o $@.out $^ -DDEBUG

clean :
	rm -f $(TARGET)