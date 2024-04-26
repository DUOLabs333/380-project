#pragma once
#include <gmp.h>
#include <math.h>

#define Z2BYTES(x, buf) mpz_export(buf,NULL,-1,1,0,0,x)

#define Z2SIZE(x) ceil((mpz_sizeinbase(x, 2)*1.0)/CHAR_BIT)
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)

#define Z2NEWBUF(x, len)\
	NEWBUF(x, len);\
	Z2BYTES(x, CONCAT(x,_buf));
