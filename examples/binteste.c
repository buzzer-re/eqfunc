#include <stdio.h>


int dummy();

void func() {
	int x = 100;
	for (int i = 0; i < 100;i++) {
		puts("Hi!");
	}
}


void func2() {
	int x = 100;
	int y = x * 100;
	for (int j = 0; j < 10; j++) {
		x = dummy();	
		y += x;
	}
}

int dummy() 
{
	return 1;
}


void main() {
	func();
	func2();
}
