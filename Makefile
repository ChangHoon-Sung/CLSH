CC = gcc
CFLAGS = -W -Wall
TARGET = clsh

all : $(TARGET)
	$(CC) $(CFLAGS) -o $@.out -g $^

run : clsh
	./$^.out -h pnode1,pnode2 "uname -a"

clsh : clsh.c
	$(CC) $(CFLAGS) -o $@.out -g $^

clean :
	rm -f $(TARGET)