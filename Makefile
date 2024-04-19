CC = gcc
CFLAGS = -Wall -Wextra -g -lpcap

TARGET = packet-analyzer

SDIR = src
ODIR = obj
BDIR = bin

SRCS := $(wildcard $(SDIR)/*.c $(SDIR)/*.h)
OBJS :=  $(patsubst $(SDIR)/%.c, $(ODIR)/%.o, $(wildcard $(SDIR)/*.c)) 

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(BDIR)
	$(CC) $(CFLAGS) -o bin/$@ $^

$(ODIR)/%.o: $(SDIR)/%.c
	mkdir -p $(ODIR)
	$(CC) $(CFLAGS) -c $< -o $@

dir:
	mkdir -p $(ODIR)

clean:
	rm -rf $(ODIR) $(BDIR)

.PHONY: all clean