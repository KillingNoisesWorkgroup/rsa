#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

typedef uint32_t lint_t;

lint_t ext_gcd(lint_t a, lint_t b, lint_t *x, lint_t *y){
	lint_t d, x1, y1, tmp;
	if(b == 0){
		*x = 1;
		*y = 0;
		return a;
	}
	d = ext_gcd(b, b%a, &x1, &y1);
	tmp = x1;
	x1 = y1;
	y1 = tmp - (a/b)*y1;
	return d;
}

lint_t inverse(lint_t a, lint_t n){
	lint_t x, y;
	ext_gcd(a, n, &x, &y);
	return x;
}

lint_t fast_pow(lint_t a, lint_t b, lint_t n){
	lint_t d;
	d = 1;
	while(b>>=1){
		if(b&1 == 1) d = d*a%n;
		a = a*a%n;
	}
	return d;
}

int main(int nargs, char **argv){
	return 0;
}
