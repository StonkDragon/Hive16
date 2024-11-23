build:
	clang main.c -pedantic -std=c99 -o h16 -DDEBUG=0 -Wall -Wextra

build-debug:
	clang main.c -pedantic -std=c99 -o h16 -DDEBUG=1 -Wall -Wextra -O0 -g

build-release:
	clang main.c -pedantic -std=c99 -o h16 -Wall -Wextra -O3
