#pragma once
#include <gmp.h>
#include <math.h>

#define min(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _b : _a; })

#define Z2BYTES(x, len, buf) mpz_export(buf,len,-1,1,0,0,x)

#define Z2SIZE(x) ceil((mpz_sizeinbase(x, 2)*1.0)/CHAR_BIT)
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(buf, len, x) mpz_import(x,len,-1,1,0,0,buf)

#define Z2NEWBUF(x, len)\
	NEWBUF(x, len);\
	Z2BYTES(x, NULL, CONCAT(x,_buf));
