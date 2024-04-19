CC = gcc
CFLAGS = -Wall -Wextra -g -lpcap
TARGET = packet-analyzer
SRCS = main.h
OBJS = $(SRCS:.h=.o)

all: $(TARGET)


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)