#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"
#include "z.h"
#include <math.h>

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x,10)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE* f, mpz_t x)
{
	size_t i,len = mpz_size(x)*sizeof(mp_limb_t);
	/* NOTE: len may overestimate the number of bytes actually required. */
	unsigned char* buf = malloc(len);
	
	Z2BYTES(x, &len, buf);
	
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b = (len >> 8*i) % 256;
		fwrite(&b,1,1,f);
	}
	fwrite(buf,1,len,f);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}
int zFromFile(FILE* f, mpz_t x)
{
	size_t i,len=0;
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b;
		/* XXX error check this; return meaningful value. */
		fread(&b,1,1,f);
		len += (b << 8*i);
	}
	unsigned char* buf = malloc(len);
	fread(buf,1,len,f);
	
	BYTES2Z(buf, len, x);

	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

int rsa_initKey(RSA_KEY* K)
{
	mpz_init(K->d); mpz_set_ui(K->d,0);
	mpz_init(K->e); mpz_set_ui(K->e,0);
	mpz_init(K->p); mpz_set_ui(K->p,0);
	mpz_init(K->q); mpz_set_ui(K->q,0);
	mpz_init(K->n); mpz_set_ui(K->n,0);
	return 0;
}

int rsa_writePublic(FILE* f, RSA_KEY* K)
{
	/* only write n,e */
	zToFile(f,K->n);
	zToFile(f,K->e);
	return 0;
}
int rsa_writePrivate(FILE* f, RSA_KEY* K)
{
	zToFile(f,K->n);
	zToFile(f,K->e);
	zToFile(f,K->p);
	zToFile(f,K->q);
	zToFile(f,K->d);
	return 0;
}
int rsa_readPublic(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K); /* will set all unused members to 0 */
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	return 0;
}
int rsa_readPrivate(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K);
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	zFromFile(f,K->p);
	zFromFile(f,K->q);
	zFromFile(f,K->d);
	return 0;
}
int rsa_shredKey(RSA_KEY* K)
{
	/* clear memory for key. */
	mpz_t* L[5] = {&K->d,&K->e,&K->n,&K->p,&K->q};
	size_t i;
	for (i = 0; i < 5; i++) {
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs) {
			memset(mpz_limbs_write(*L[i],nLimbs),0,nLimbs*sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}

char* rsa_get_full_file_name(const char* fn, int priv){
    char* suffix;
    if (priv){
        suffix="";
    }else{
        suffix=".pub";
    }
    
    int fn_len=strlen(fn);
    int suffix_len=strlen(suffix);
    
    char* filename=malloc(fn_len+suffix_len+1); //While filenames on Linux are limited to 255 bytes, the full paths are not. So, we allocate enough space for basenames (filenames without extensions) that are 255, so we can fit the rest in.
    
    memcpy(filename, fn, fn_len);
    memcpy(filename+fn_len, suffix, suffix_len);
    filename[fn_len+suffix_len]=0;
    
    return filename;
}


void rsa_generate_keys(char* fn_prefix, mpz_t dh_p)
{
	RSA_KEY K;
	rsa_initKey(&K);

	 mpz_t* keys[2]= {&K.p, &K.q}; //Has to be an array of pointers; in C, arrays (which is what mpz_t is under the hood) are not assignable
	 
	 NEWZ(p_q); //|p-q|
	 
	 int keyBytes=2*Z2SIZE(dh_p)+2; //Size of the key used (n). Has to be > 2*len(dh_p) and has to be even
	 int pBytes=keyBytes/2; //Size of the prime numbers (p and q)
	 
	 //Compare p and q
	 unsigned char* buf=malloc(pBytes);
	 for (int i=0; i< 2; i++){
    	 while(1){
    	   randBytes(buf,pBytes);
    	   BYTES2Z(buf, pBytes, *keys[i]);
    	   
    	   mpz_sub(p_q,K.p,K.q);
           mpz_abs(p_q,p_q);
	   mpz_mul(K.n, K.p, K.q); //n=p*q
    	   if ((ISPRIME(*keys[i])>0) && (mpz_cmp_ui(p_q,100000)>0) && (Z2SIZE(K.n)==keyBytes)){ //Technically, we should check that ISPRIME(...)==2, but it will likely take a long time to get a probable pime. Additionally, the distance between p and q could be set higher.
    	       break;
    	   }
        }
    }
  
  
  NEWZ(p_1); //p-1
  mpz_sub_ui(p_1, K.p, 1);
  
  NEWZ(q_1); //q-1
  mpz_sub_ui(q_1, K.q, 1);
  
  NEWZ(totient); // totient(n)=lcm(totient(p),totient(q))=lcm(p-1,q-1); totient(n)=(p-1)(q-1) will also work (since it is divisible by lcm(p-1,q-1))
  mpz_lcm(totient, p_1, q_1);
  
  //Generating e
  NEWZ(modulus); //((totient-1)-3+1)=totient-3
  mpz_sub_ui(modulus, totient, 3);
  
  NEWZ(gcd_e_tot); //gcd(e, totient)
  while(1){
      randBytes(buf,pBytes);
      BYTES2Z(buf, pBytes, K.e); //2 < e < totient -> 3 <= e <= totient-1 -> (rand()%((totient-1)-3+1))+3
      mpz_mod(K.e, K.e, modulus);
      mpz_add_ui(K.e, K.e, 3);
      
      mpz_gcd(gcd_e_tot, K.e, totient);
      if (mpz_cmp_ui(gcd_e_tot, 1)==0){ //gcd(e, totient)==1. We could just just hardcode e=3, but that could lose some entropy
        break;
      }
  }
  
  //Computing d
  //Since e and totient were specifically chosen to be co-prime, then e*d+totient*t=1 (due to Bézout's identity). This means that e*d =1 mod n -> d=e^(-1) mod n
  mpz_gcdext(NULL, K.d, NULL, K.e, totient); //a*s+b*t=g
  
  while(mpz_cmp_si(K.d,0)<=0){ //Forces d to be positive. Not the most efficient, but given the unwieldy C interface, this is easier to reason about
    mpz_add(K.d,K.d,totient);
  }
  
  free(buf);

   char* fn;
   FILE* file;
   fn=rsa_get_full_file_name(fn_prefix, 1);
   file=fopen(fn, "w");
   rsa_writePrivate(file, &K);

   fclose(file);
   free(fn);

   fn=rsa_get_full_file_name(fn_prefix, 0);
   file=fopen(fn, "w");
   rsa_writePublic(file, &K);

   fclose(file);
   free(fn);

   rsa_shredKey(&K);

}

void rsa_encrypt(RSA_KEY* K, char* inBuf, size_t len, char* outBuf)
{
	 
	 NEWZ(ciphertext);
	 
	 NEWZ(m);
	 BYTES2Z(inBuf, len, m);
	 
	 
	 mpz_powm(ciphertext, m, K->e, K->n); //c=m^e mod n
	 
	 size_t size=0;

	 Z2BYTES(ciphertext, NULL, outBuf);
}

void rsa_decrypt(RSA_KEY* K, char* outBuf, size_t outLen, char* inBuf, size_t inLen)
{
	
	NEWZ(ciphertext);
    BYTES2Z(outBuf, outLen, ciphertext);
    
    NEWZ(m);
    mpz_powm(m, ciphertext, K->d, K->n); // c^d=(m^e)^d = m mod n
    
    size_t buflen;
    char* buf=Z2BYTES(m, &buflen, NULL);

    memcpy(inBuf, buf, min(inLen, buflen)); //Don't want to overflow inBuf
    free(buf);
}

int rsa_load_keys(char* keyPath, RSA_KEY* key, int priv){
	FILE* file=fopen(keyPath, "r");
	if (file == NULL){
		return -1;
	}

	if (priv){
		rsa_readPrivate(file, key);
	}else{
		rsa_readPublic(file, key);
	}
	fclose(file);
	return 0;
}
