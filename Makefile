CC      ?= cc
CFLAGS  ?= -std=c99 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror -pedantic -O1 -g
SAN     ?= -fsanitize=address,undefined -fno-sanitize-recover=all
ROUNDS  ?= 300000

build/test_engine: src/mgus_engine.c src/mgus_engine.h tests/unit/test_engine.c
	mkdir -p build
	$(CC) $(CFLAGS) $(SAN) -Isrc src/mgus_engine.c tests/unit/test_engine.c -o $@

test: build/test_engine
	./build/test_engine $(ROUNDS)

clean:
	rm -rf build

.PHONY: test clean
