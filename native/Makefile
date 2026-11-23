CC      ?= cc
CFLAGS  ?= -O2 -Wall

all: file_processor

file_processor: file_processor.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f file_processor
