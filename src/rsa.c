#define _GNU_SOURCE
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define PRIME 0
#define COMPOSITE 1

#define FALSE 0
#define TRUE 1

#define CHECK_MR if(miller_rabin(a, s) == PRIME) printf("+"); else printf("-")

typedef struct rsa_key{
	BIGNUM *x;
	BIGNUM *n;
} rsa_key;

rsa_key* rsa_key_new(){
	rsa_key *ret;
	if((ret = malloc(sizeof(rsa_key))) == NULL){
		perror("malloc");
		exit(1);
	}
	ret->x = BN_new(); ret->n = BN_new();
	return ret;
}

void rsa_key_free(rsa_key *k){
	BN_free(k->x); BN_free(k->n);
	free(k);
}

void rsa_key_print(FILE *stream, rsa_key *rsa){
	BN_print_fp(stream, rsa->x);
	fprintf(stream, "\n");
	BN_print_fp(stream, rsa->n);
	fprintf(stream, "\n");
}

rsa_key* rsa_key_read(FILE *stream){
	char *buf = NULL;
	rsa_key *rsa;
	int size;
	rsa = rsa_key_new();
	getline(&buf, &size, stream);
	BN_hex2bn(&rsa->x, buf);
	getline(&buf, &size, stream);
	BN_hex2bn(&rsa->n, buf);
	free(buf);
	return rsa;
}

int witness(BIGNUM* a, BIGNUM* n){
	BIGNUM *b, *c, *d, *tmp_c;
	BN_CTX *tmp;
	b = BN_new(); c = BN_new(); d = BN_new(); tmp_c = BN_new();
	BN_one(d);								// d = 1
	BN_sub(b, n, d);						// b = n - 1
	BN_copy(tmp_c, b);						// tmp_c = n - 1
	tmp = BN_CTX_new();
	while(!BN_is_zero(b)){
		if(BN_is_bit_set(b, 0)){
			BN_mod_mul(d, d, a, n, tmp);	// d = d*a mod n
		}
		BN_copy(c, a);						// c = a
		BN_mod_mul(a, a, a, n, tmp);		// a = a*a mod n
		if((BN_is_one(a) && !BN_is_one(c)) && (BN_cmp(c, tmp_c))){
			BN_free(b); BN_free(c); BN_free(d); BN_free(tmp_c); BN_CTX_free(tmp);
			return TRUE;
		}
		BN_rshift1(b, b);
	}
	if(!BN_is_one(d)){
		BN_free(b); BN_free(c); BN_free(d); BN_free(tmp_c); BN_CTX_free(tmp);
		return TRUE;
	}
	BN_free(b); BN_free(c); BN_free(d); BN_free(tmp_c); BN_CTX_free(tmp);
	return FALSE;
}

int miller_rabin(BIGNUM* n, int s){
	int i;
	BIGNUM *a, *b, *c, *d;
	a = BN_new(); b = BN_new(); c = BN_new(); d = BN_new();
	BN_one(d);								// d = 1
	BN_copy(c, n);							// c = n
	BN_sub_word(c, 1); BN_sub_word(c, 1);	// c = n - 2
	for(i = 1; i < s; i++){
		BN_rand_range(a, c);				// a = rand(0, n-3)
		BN_add(b, a, d);					// b = a + b, so b = rand(1, n-2)
		BN_add(b, b, d);					// b = a + b, so b = rand(2, n-1)
		if(witness(b, n) == TRUE){
			BN_free(a); BN_free(b); BN_free(c); BN_free(d);
			return COMPOSITE;
		}
	}
	BN_free(a); BN_free(b); BN_free(c); BN_free(d);
	return PRIME;
}

void generate_prime(BIGNUM** p, int bits, int attempts){
	int i;
	for(i = 0; i < attempts; i++){
		BN_rand(*p, bits, 1, 1);
		if(miller_rabin(*p, 40) == PRIME) break;
	}
}

void ext_gcd(BIGNUM *a, BIGNUM *b, BIGNUM *x, BIGNUM *y, BIGNUM *d){
	BIGNUM *d1, *x1, *y1, *mod;
	BN_CTX *ctx;
	if(BN_is_zero(b)){
		BN_one(x);							// x = 1
		BN_zero(y);							// y = 0
		BN_copy(d, a);						// d = a
		return;
	}
	d1 = BN_new(); x1 = BN_new(); y1 = BN_new(); mod = BN_new(); ctx = BN_CTX_new();
	BN_mod(mod, a, b, ctx);					// mod = a % b
	ext_gcd(b, mod, x1, y1, d1);
	BN_copy(d, d1);							// d = d1
	BN_copy(x, y1);							// x = y1
	BN_div(d1, NULL, a, b, ctx);			// d1 = a / b
	BN_mul(d1, d1, y1, ctx);				// d1 = d1 * y1
	BN_sub(y, x1, d1);						// y = x1 - d1
	BN_free(d1); BN_free(x1); BN_free(y1); BN_free(mod);
}

void fast_pow(BIGNUM *ret, BIGNUM *a, BIGNUM *b, BIGNUM *n){
	BIGNUM *a1, *b1;
	BN_CTX *ctx;
	a1 = BN_new(); b1 = BN_new();
	BN_copy(a1, a); BN_copy(b1, b); ctx = BN_CTX_new();
	BN_one(ret);
	while(!BN_is_zero(b1)){
		if(BN_is_bit_set(b1, 0)) BN_mod_mul(ret, ret, a1, n, ctx);
		BN_mod_mul(a1, a1, a1, n, ctx);
		BN_rshift1(b1, b1);
	}
	BN_free(a1); BN_free(b1); BN_CTX_free(ctx);
}

void rsa_keygen(rsa_key *public, rsa_key *private, int bits){
	BIGNUM *p, *q, *n, *e, *fi, *tmp_d, *tmp_x, *tmp_y;
	BN_CTX *ctx;
	p = BN_new(); q = BN_new(); n = BN_new(); e = BN_new(); fi = BN_new(); ctx = BN_CTX_new();
	tmp_x = BN_new(); tmp_y = BN_new(); tmp_d = BN_new();
	generate_prime(&p, bits/2, bits*2); generate_prime(&q, bits/2, bits*2);
	BN_mul(n, p, q, ctx);
	BN_copy(public->n, n); BN_copy(private->n, n);
	BN_sub_word(p, 1); BN_sub_word(q, 1);
	BN_mul(fi, p, q, ctx);
	BN_set_word(e, 65537);
	ext_gcd(e, fi, tmp_x, tmp_y, tmp_d);
	if(BN_is_negative(tmp_x)) BN_add(tmp_x, tmp_x, fi);
	BN_copy(private->x, tmp_x);
	BN_copy(public->x, e);
	BN_free(p); BN_free(q); BN_free(n); BN_free(e); BN_free(fi); 
	BN_free(tmp_x); BN_free(tmp_y); BN_free(tmp_d); BN_CTX_free(ctx);
}

void crypt_msg(BIGNUM *ret, BIGNUM *msg, rsa_key *k){
	fast_pow(ret, msg, k->x, k->n);
}

void encrypt(const char *src, const char *dst, const char *key){
	FILE *key_file, *src_file, *dst_file;
	int size, block_size;
	unsigned char* buf;
	rsa_key* k;
	BIGNUM* msg;
	
	msg = BN_new();
	
	if((key_file = fopen(key, "r")) == NULL){
		perror("fopen");
		exit(1);
	}
	if((src_file = fopen(src, "rb")) == NULL){
		perror("fopen");
		exit(1);
	}
	if((dst_file = fopen(dst, "w+b")) == NULL){
		perror("fopen");
		exit(1);
	}
	
	k = rsa_key_read(key_file);
	block_size = BN_num_bytes(k->n);
	
	if((buf = malloc(block_size)) == NULL){
		perror("malloc");
		exit(1);
	}
	
	while((size = fread(buf, sizeof(char), block_size - 1, src_file)) > 0){
		BN_bin2bn(buf, size, msg);
		crypt_msg(msg, msg, k);
		bzero(buf, block_size);
		fwrite(buf, sizeof(char), block_size - BN_num_bytes(msg), dst_file);
		BN_bn2bin(msg, buf);
		fwrite(buf, sizeof(char), BN_num_bytes(msg), dst_file);
		fwrite(&size, sizeof(size), 1, dst_file);
	}
	BN_free(msg);
	free(buf);
	fclose(key_file);
	fclose(dst_file);
	fclose(src_file);
	rsa_key_free(k);
}

void decrypt(const char *src, const char *dst, const char *key){
	FILE *key_file, *src_file, *dst_file;
	int size, block_size;
	unsigned char* buf;
	rsa_key* k;
	BIGNUM* msg;
	
	msg = BN_new();
	
	if((key_file = fopen(key, "r")) == NULL){
		perror("fopen");
		exit(1);
	}
	if((src_file = fopen(src, "rb")) == NULL){
		perror("fopen");
		exit(1);
	}
	if((dst_file = fopen(dst, "w+b")) == NULL){
		perror("fopen");
		exit(1);
	}
	
	k = rsa_key_read(key_file);
	block_size = BN_num_bytes(k->n);
	
	if((buf = malloc(block_size)) == NULL){
		perror("malloc");
		exit(1);
	}
	
	while(fread(buf, sizeof(char), block_size, src_file) > 0){
		BN_bin2bn(buf, block_size, msg);
		crypt_msg(msg, msg, k);
		bzero(buf, block_size - 1);
		fread(&size, sizeof(size), 1, src_file);
		fwrite(buf, sizeof(char), size - BN_num_bytes(msg), dst_file);
		BN_bn2bin(msg, buf);
		fwrite(buf, sizeof(char), BN_num_bytes(msg), dst_file);
	}
	BN_free(msg);
	free(buf);
	fclose(key_file);
	fclose(dst_file);
	fclose(src_file);
	rsa_key_free(k);
}

void generate_to_file(const char *pub, const char *pri, int bits){
	FILE *file1, *file2;
	rsa_key *public, *private;
	if((file1 = fopen(pub, "w")) == NULL){
		perror("fopen");
		exit(1);
	}
	if((file2 = fopen(pri, "w")) == NULL){
		perror("fopen");
		exit(1);
	}
	if((chmod(pri, S_IRUSR | S_IWUSR | S_IXUSR)) == -1){
		perror("fchmod");
		exit(1);
	}
	public = rsa_key_new(); private = rsa_key_new();
	rsa_keygen(public, private, bits);
	rsa_key_print(file1, public);
	rsa_key_print(file2, private);
	rsa_key_free(public); rsa_key_free(private);
}

void help(char** argv){
	printf("Usage: %s {-g public private num | -e src dst key | -d src dst key}\n", argv[0]);
	printf("%5s: generates public and private files with keys of num bits length\n", "-g");
	printf("%5s: encodes src file to dst file with given key file\n", "-e");
	printf("%5s: decodes src file to dst file with given key file\n", "-d");
	exit(1);
}

int main(int nargs, char** argv){
	BIGNUM *msg;
	msg = BN_new();
	FILE *f_pub, *f_priv;
	rsa_key *pub, *priv;
	char *msg_n;
	if(nargs != 5) help(argv);
	if(!strcmp(argv[1], "-g")){
		generate_to_file(argv[2], argv[3], atoi(argv[4]));
	} else {
		if(!strcmp(argv[1], "-e")){
			encrypt(argv[2], argv[3], argv[4]);
		} else {
			if(!strcmp(argv[1], "-d")){
				decrypt(argv[2], argv[3], argv[4]);
			} else help(argv);
		}
	}
	return 1;
}
