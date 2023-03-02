#include <stdio.h>
#include <stdlib.h>

typedef void(*FUNC)();

void foo() {
	puts("foo");
}

void indirectCall(FUNC pointer) {
	if (NULL == pointer) {
		return;
	}
	return pointer();
}

int directCall(int var) {
	return var >> 1;
}

int indirectJump(int var) {
	switch (var) {
		case 0: break;
		case 1: --var; break;
		case 2: var -= 2; break;
		case 3: var -= 3; break;
		case 4: var -= 4; break;
		case 5: var -= 5; break;
		case 6: var -= 6; break;
	}
	return var;
}

int indirectJumpMirror(int var) {
	switch (var) {
		case 0: break;
		case 1: --var; break;
		case 2: var -= 2; break;
		case 3: var -= 3; break;
		case 4: var -= 4; break;
		case 5: var -= 5; break;
		case 6: var -= 6; break;
	}
	return var;
}

int fib(int n) {
	if (n <= 2) {
		return 1;
	}
	return fib(n-1) + fib(n-2);
}

int main() {
	int b = 10;

	puts("indirectCall");
	indirectCall(foo);

	fib(b);

	puts("directCall");
	b = directCall(b);

	puts("indirectJump");
	b = indirectJump(b);

	if (b) {
		puts("b != 0");
	} else {
		puts("b == 0");
	}

	puts("indirectJumpMirror");
	b = indirectJump(b);

	fib(b);
	
	puts("indirectCall");
	indirectCall(foo);


	return 0;
}
