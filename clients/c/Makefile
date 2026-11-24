CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Werror -std=c99

all: kopacz

kopacz: kopacz.c
	$(CC) $(CFLAGS) kopacz.c -o kopacz

clean:
	rm -f kopacz

.PHONY: all clean
