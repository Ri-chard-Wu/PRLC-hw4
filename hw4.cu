//***********************************************************************************
// 2018.04.01 created by Zexlus1126
//
//    Example 002
// This is a simple demonstration on calculating merkle root from merkle branch 
// and solving a block (#286819) which the information is downloaded from Block Explorer 
//***********************************************************************************

#include <iostream>
#include <fstream>
#include <string>
#include <cstdio>
#include <cstring>
#include <cassert>
#include <chrono>

#include "sha256.h"
using namespace std::chrono;
using namespace std;

#define N_TSK_EXP 32
#define N_TSK_PER_THRD_EXP 14
#define N_THRD_EXP (N_TSK_EXP - N_TSK_PER_THRD_EXP) // 18
#define N_THRD_PER_BLK_EXP 7  

#define N_BLK (1 << (N_THRD_EXP - N_THRD_PER_BLK_EXP)) // 2048 (2560 SM's)
#define N_THRD_PER_BLK (1 << (N_THRD_PER_BLK_EXP)) // 128
#define N_TSK_PER_THRD (1 << (N_TSK_PER_THRD_EXP)) // 16384

// #define N_BLK 2560 
// #define N_THRD_PER_BLK 256
// #define N_TSK_PER_THRD 6554 



// sm[0 - 79]: raw blk header.
// sm[80 - 111]: sha of common part of header.
// sm[112 - 143]: target difficulty.

// #define BASE_ADDR_RAW_BLKHDR 0
// #define BASE_ADDR_BLKHDR_COMMON_SHA 80
// #define BASE_ADDR_TD 112
// #define BASE_ADDR_THRD_LOCAL_SM 144
// #define SIZE_THRD_LOCAL_SM 320

#define BASE_ADDR_RAW_BLKHDR (40960 >> 2)
#define BASE_ADDR_BLKHDR_COMMON_SHA ((40960 + 80) >> 2)
#define BASE_ADDR_TD ((40960 + 112) >> 2)

#define BASE_ADDR_THRD_LOCAL_SM 0
#define SIZE_THRD_LOCAL_SM (320 >> 2)



typedef struct
{
  BYTE b[4];
} byte_group_t;


////////////////////////   Block   /////////////////////

typedef struct _block
{
    unsigned int version;
    unsigned char prevhash[32];
    unsigned char merkle_root[32];
    unsigned int ntime;
    unsigned int nbits;
    unsigned int nonce;
}HashBlock;

#define BLK_HDR_SIZE 80

// sizeof(block) == 80 (bytes).



////////////////////////   Utils   ///////////////////////

//convert one hex-codec char to binary
unsigned char decode(unsigned char c)
{
    switch(c)
    {
        case 'a':
            return 0x0a;
        case 'b':
            return 0x0b;
        case 'c':
            return 0x0c;
        case 'd':
            return 0x0d;
        case 'e':
            return 0x0e;
        case 'f':
            return 0x0f;

        case '0' ... '9':
            return c-'0';
    }
}



// `in` is a string of 64 char's, 
    // e.g. "7938131056d5e703b8638cf3cb937755c8be0f1909f44e2a1886fbd2fbca43e0",
    // from file `casexx.in`.

// `out` is its 256-bit representation.

void convert_string_to_little_endian_bytes(unsigned char* out, char *in, size_t string_len)
{
    assert(string_len % 2 == 0);

    size_t s = 0;
    size_t b = string_len/2-1;

    for(s, b; s < string_len; s+=2, --b)
    {
        out[b] = (unsigned char)(decode(in[s])<<4) + decode(in[s+1]);
    }
}



// print out binary array (from highest value) in the hex format
void print_hex(unsigned char* hex, size_t len)
{
    for(int i=0;i<len;++i)
    {
        printf("%02x", hex[i]);
    }
}

// print out binar array (from lowest value) in the hex format
void print_hex_inverse(unsigned char* hex, size_t len)
{
    for(int i=len-1;i>=0;--i)
    {
        printf("%02x", hex[i]);
    }
}


void getline(char *str, size_t len, FILE *fp)
{

    int i=0;
    while( i<len && (str[i] = fgetc(fp)) != EOF && str[i++] != '\n');
    str[len-1] = '\0';
}


void double_sha256(SHA256 *sha256_ctx, unsigned char *bytes, size_t len)
{
    SHA256 tmp;

    // tmp = hash(list[i]+list[i+1]), i: 0 ~ txLen - 1, i += 2.
    sha256(&tmp, (BYTE*)bytes, len);   
    
    // list[j] = hash(tmp), j: 0 ~ txLen / 2 - 1, j += 1.    
    sha256(sha256_ctx, (BYTE*)&tmp, sizeof(tmp));
}

void calc_merkle_root(unsigned char *root, int count, char **branch)
{
    size_t total_count = count; // merkle branch
    unsigned char *raw_list = new unsigned char[(total_count+1)*32]; // `*32`: 256 bits == 32 bytes.
    unsigned char **list = new unsigned char*[total_count+1];

    // copy each branch to the list
    for(int i=0; i < total_count; ++i)
    {
        list[i] = raw_list + i * 32;
        convert_string_to_little_endian_bytes(list[i], branch[i], 64);
    }

    list[total_count] = raw_list + total_count * 32;


    // calculate merkle root
    while(total_count > 1)
    {
        
        // hash each pair
        int i, j;

        if(total_count % 2 == 1)  //odd, 
        {
            // void *memcpy(void *dest, const void * src, size_t n).
            memcpy(list[total_count], list[total_count-1], 32);
        }



        for(i=0, j=0; i < total_count; i += 2, ++j)
        {

            // double_sha:
            //     tmp = hash(list[0]+list[1])
            //     list[0] = hash(tmp)
            double_sha256((SHA256*)list[j], list[i], 64);
        }

        total_count = j; // halved in each iteration.
    }

    memcpy(root, list[0], 32);

    delete[] raw_list;
    delete[] list;
}






// ###############################################################################


// __device__ 
// int little_endian_bit_comparison_dev(const unsigned char *a, 
//                                         const unsigned char *b){
    
__device__ 
int little_endian_bit_comparison_dev(const byte_group_t *a, 
                                        const unsigned char *b){


    // for(int i = 32 - 1; i >= 0; --i)
    // {
    //     if(a[i] < b[i])
    //         return -1;
    //     else if(a[i] > b[i])
    //         return 1;
    // }


    for(int i = 7; i >= 0; --i)
    {
        for(int j = 3; j >= 0; --j){
            
            if(a[N_THRD_PER_BLK * i].b[j] < b[4 * i + j])
                return -1;
            else if(a[N_THRD_PER_BLK * i].b[j] > b[4 * i + j])
                return 1;
        }

    }
    
    return 0;
}


__device__
void sha256_transform_dev(SHA256 *ctx, const BYTE *msg){
	
    WORD a, b, c, d, e, f, g, h;
	WORD i, j;
	

	WORD w[64];

	for(i=0, j=0; i < 16; ++i, j += 4)
	{
		w[i] = (msg[j]<<24) | (msg[j+1]<<16) | (msg[j+2]<<8) | (msg[j+3]);
	}
	

	for( i = 16; i < 64; ++i)
	{
		WORD s0 = (_rotr(w[i-15], 7)) ^ (_rotr(w[i-15], 18)) ^ (w[i-15] >> 3);
		WORD s1 = (_rotr(w[i-2], 17)) ^ (_rotr(w[i-2], 19))  ^ (w[i-2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	

	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];
	f = ctx->h[5];
	g = ctx->h[6];
	h = ctx->h[7];
	

	for(i=0;i<64;++i)
	{
		WORD S0 = (_rotr(a, 2)) ^ (_rotr(a, 13)) ^ (_rotr(a, 22));
		WORD S1 = (_rotr(e, 6)) ^ (_rotr(e, 11)) ^ (_rotr(e, 25));
		WORD ch = (e & f) ^ ((~e) & g);
		WORD maj = (a & b) ^ (a & c) ^ (b & c);
		WORD temp1 = h + S1 + ch + k_dev[i] + w[i];
		WORD temp2 = S0 + maj;
		
		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}


	ctx->h[0] += a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += e;
	ctx->h[5] += f;
	ctx->h[6] += g;
	ctx->h[7] += h;
	
}











__device__ 
void sha256_commonBlkhdr_dev(SHA256 *ctx, const BYTE *msg){

	ctx->h[0] = 0x6a09e667;
	ctx->h[1] = 0xbb67ae85;
	ctx->h[2] = 0x3c6ef372;
	ctx->h[3] = 0xa54ff53a;
	ctx->h[4] = 0x510e527f;
	ctx->h[5] = 0x9b05688c;
	ctx->h[6] = 0x1f83d9ab;
	ctx->h[7] = 0x5be0cd19;

	sha256_transform_dev(ctx, &msg[0]);
}








__device__ 
void sha256_stage1_dev(byte_group_t *sm, unsigned int nonce){

	WORD i, j;
    WORD a, b, c, d, e, f, g, h;



    // BYTE msg[64] = {0}; // --------------------------------- 64 bytes

    byte_group_t *msg;
    msg = &sm[BASE_ADDR_THRD_LOCAL_SM + threadIdx.x];
    for(int i=0; i < 16; i++){
        ((WORD *)&msg[N_THRD_PER_BLK * i])[0] = 0;
    }




    // WORD w[64]; // --------------------------------- 256 bytes

    WORD *w;
    w = (WORD *)&sm[BASE_ADDR_THRD_LOCAL_SM + 2048 + threadIdx.x];




    // ((WORD *)(&msg[12]))[0] = nonce;
    ((WORD *)(&msg[N_THRD_PER_BLK * 3]))[0] = nonce;




	// for(i=0; i < 12; ++i) 
	// {
	// 	msg[i] = ((BYTE *)&sm[BASE_ADDR_RAW_BLKHDR])[i + 64];
	// }

    #pragma unroll
	for(i=0; i < 3; ++i) 
	{
        ((WORD *)&msg[N_THRD_PER_BLK * i])[0] = ((WORD *)&sm[BASE_ADDR_RAW_BLKHDR])[i + 16];
	}




	// msg[16] = 0x80;  
    msg[N_THRD_PER_BLK * 4].b[0] = 0x80;  



	// msg[63] = 640;
	// msg[62] = 2;
	// msg[61] = 0;
	// msg[60] = 0;
    msg[N_THRD_PER_BLK * 15].b[3] = 640;  
    msg[N_THRD_PER_BLK * 15].b[2] = 2;  
    msg[N_THRD_PER_BLK * 15].b[1] = 0;  
    msg[N_THRD_PER_BLK * 15].b[0] = 0;  



	// msg[59] = 0;
	// msg[58] = 0;
	// msg[57] = 0;
	// msg[56] = 0;
    msg[N_THRD_PER_BLK * 14].b[3] = 0;  
    msg[N_THRD_PER_BLK * 14].b[2] = 0;  
    msg[N_THRD_PER_BLK * 14].b[1] = 0;  
    msg[N_THRD_PER_BLK * 14].b[0] = 0;  



    // #############################################



	// for(i=0, j=0; i < 16; ++i, j += 4)
	// {
	// 	w[i] = (msg[j]<<24) | (msg[j+1]<<16) | (msg[j+2]<<8) | (msg[j+3]);
	// }

	for(i=0; i < 16; ++i)
	{
		w[N_THRD_PER_BLK * i] = (msg[N_THRD_PER_BLK * i].b[0]<<24) | \
                (msg[N_THRD_PER_BLK * i].b[1]<<16)| \
                (msg[N_THRD_PER_BLK * i].b[2]<<8) | \
                (msg[N_THRD_PER_BLK * i].b[3]);
	}


	// for( i = 16; i < 64; ++i)
	// {
	// 	WORD s0 = (_rotr(w[i-15], 7)) ^ (_rotr(w[i-15], 18)) ^ (w[i-15] >> 3);
	// 	WORD s1 = (_rotr(w[i-2], 17)) ^ (_rotr(w[i-2], 19))  ^ (w[i-2] >> 10);
	// 	w[i] = w[i-16] + s0 + w[i-7] + s1;
	// }


	for( i = 16; i < 64; ++i)
	{
		WORD s0 = (_rotr(w[N_THRD_PER_BLK * (i-15)], 7)) ^ \
                  (_rotr(w[N_THRD_PER_BLK * (i-15)], 18)) ^ \
                  (w[N_THRD_PER_BLK * (i-15)] >> 3);

		WORD s1 = (_rotr(w[N_THRD_PER_BLK * (i-2)], 17)) ^ \
                  (_rotr(w[N_THRD_PER_BLK * (i-2)], 19)) ^ \
                  (w[N_THRD_PER_BLK * (i-2)] >> 10);

		w[N_THRD_PER_BLK * i] = w[N_THRD_PER_BLK * (i-16)] + \
                                    s0 + w[N_THRD_PER_BLK * (i-7)] + s1;
	}


	// a = tmp->h[0];
	// b = tmp->h[1];
	// c = tmp->h[2];
	// d = tmp->h[3];
	// e = tmp->h[4];
	// f = tmp->h[5];
	// g = tmp->h[6];
	// h = tmp->h[7];

	a = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[0];
	b = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[1];
	c = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[2];
	d = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[3];
	e = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[4];
	f = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[5];
	g = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[6];
	h = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[7];



	for(i=0; i < 64; ++i)
	{
		WORD S0 = (_rotr(a, 2)) ^ (_rotr(a, 13)) ^ (_rotr(a, 22));
		WORD S1 = (_rotr(e, 6)) ^ (_rotr(e, 11)) ^ (_rotr(e, 25));
		WORD ch = (e & f) ^ ((~e) & g);
		WORD maj = (a & b) ^ (a & c) ^ (b & c);
		WORD temp1 = h + S1 + ch + k_dev[i] + w[N_THRD_PER_BLK * i];
		WORD temp2 = S0 + maj;
		
		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}


	// tmp->h[0] += a;
	// tmp->h[1] += b;
	// tmp->h[2] += c;
	// tmp->h[3] += d;
	// tmp->h[4] += e;
	// tmp->h[5] += f;
	// tmp->h[6] += g;
	// tmp->h[7] += h;

    for(int i=0; i < 16; i++){
        ((WORD *)&msg[N_THRD_PER_BLK * i])[0] = 0;
    }

	((WORD *)&msg[N_THRD_PER_BLK * 0])[0] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[0] + a;
	((WORD *)&msg[N_THRD_PER_BLK * 1])[0] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[1] + b;
	((WORD *)&msg[N_THRD_PER_BLK * 2])[0] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[2] + c;
	((WORD *)&msg[N_THRD_PER_BLK * 3])[0] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[3] + d;
	((WORD *)&msg[N_THRD_PER_BLK * 4])[0] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[4] + e;
	((WORD *)&msg[N_THRD_PER_BLK * 5])[0] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[5] + f;
	((WORD *)&msg[N_THRD_PER_BLK * 6])[0] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[6] + g;
	((WORD *)&msg[N_THRD_PER_BLK * 7])[0] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[7] + h;



    // #############################################

	// for(i = 0; i < 32 ; i += 4)
	// {
    //     _swap(tmp->b[i], tmp->b[i+3]);
    //     _swap(tmp->b[i+1], tmp->b[i+2]);
	// }

	for(i = 0; i < 8 ; i += 1)
	{
       
        _swap(msg[N_THRD_PER_BLK * i].b[0], msg[N_THRD_PER_BLK * i].b[3]);
        _swap(msg[N_THRD_PER_BLK * i].b[1], msg[N_THRD_PER_BLK * i].b[2]);
        
	}

}










// __device__ 
// void sha256_stage2_dev(SHA256 *ctx, const BYTE *tmp, byte_group_t *sm){


__device__ 
void sha256_stage2_dev(byte_group_t *sm){
	
	WORD i, j;
    WORD a, b, c, d, e, f, g, h;	


    // BYTE msg[64] = {};

    byte_group_t *msg;
    msg = &sm[BASE_ADDR_THRD_LOCAL_SM + threadIdx.x];
    // for(int i=0; i < 16; i++){
    //     ((WORD *)&msg[N_THRD_PER_BLK * i])[0] = 0;
    // }


	// WORD w[64];

    WORD *w;
    w = (WORD *)&sm[BASE_ADDR_THRD_LOCAL_SM + 2048 + threadIdx.x];

    
	
	// for(i=0; i < 32; ++i) 
	// {
	// 	msg[i] = tmp[i];
	// }

	// for(i=0; i < 8; ++i) 
	// {
	// 	((WORD *)&msg[N_THRD_PER_BLK * i])[0] = ((WORD *)tmp)[i];
	// }



    
	// msg[32] = 0x80;  
    msg[N_THRD_PER_BLK * 8].b[0] = 0x80;  

	// msg[63] = 256;
	// msg[62] = 1;
	// msg[61] = 0;
	// msg[60] = 0;
    msg[N_THRD_PER_BLK * 15].b[3] = 256;  
    msg[N_THRD_PER_BLK * 15].b[2] = 1;  
    msg[N_THRD_PER_BLK * 15].b[1] = 0;  
    msg[N_THRD_PER_BLK * 15].b[0] = 0;  


	// msg[59] = 0;
	// msg[58] = 0;
	// msg[57] = 0;
	// msg[56] = 0;
    msg[N_THRD_PER_BLK * 14].b[3] = 0;  
    msg[N_THRD_PER_BLK * 14].b[2] = 0;  
    msg[N_THRD_PER_BLK * 14].b[1] = 0;  
    msg[N_THRD_PER_BLK * 14].b[0] = 0;  



    // ########################################	

	// for(i=0, j=0; i < 16; ++i, j += 4)
	// {
	// 	w[i] = (msg[j]<<24) | (msg[j+1]<<16) | (msg[j+2]<<8) | (msg[j+3]);
	// }

	for(i=0; i < 16; ++i)
	{
		w[N_THRD_PER_BLK * i] = (msg[N_THRD_PER_BLK * i].b[0]<<24) | \
                (msg[N_THRD_PER_BLK * i].b[1]<<16)| \
                (msg[N_THRD_PER_BLK * i].b[2]<<8) | \
                (msg[N_THRD_PER_BLK * i].b[3]);
	}




	// for( i = 16; i < 64; ++i)
	// {
	// 	WORD s0 = (_rotr(w[i-15], 7)) ^ (_rotr(w[i-15], 18)) ^ (w[i-15] >> 3);
	// 	WORD s1 = (_rotr(w[i-2], 17)) ^ (_rotr(w[i-2], 19))  ^ (w[i-2] >> 10);
	// 	w[i] = w[i-16] + s0 + w[i-7] + s1;
	// }

	for( i = 16; i < 64; ++i)
	{
		WORD s0 = (_rotr(w[N_THRD_PER_BLK * (i-15)], 7)) ^ \
                  (_rotr(w[N_THRD_PER_BLK * (i-15)], 18)) ^ \
                  (w[N_THRD_PER_BLK * (i-15)] >> 3);

		WORD s1 = (_rotr(w[N_THRD_PER_BLK * (i-2)], 17)) ^ \
                  (_rotr(w[N_THRD_PER_BLK * (i-2)], 19)) ^ \
                  (w[N_THRD_PER_BLK * (i-2)] >> 10);

		w[N_THRD_PER_BLK * i] = w[N_THRD_PER_BLK * (i-16)] + \
                                    s0 + w[N_THRD_PER_BLK * (i-7)] + s1;
	}



	a = 0x6a09e667;
	b = 0xbb67ae85;
	c = 0x3c6ef372;
	d = 0xa54ff53a;
	e = 0x510e527f;
	f = 0x9b05688c;
	g = 0x1f83d9ab;
	h = 0x5be0cd19;
	

	for(i=0;i<64;++i)
	{
		WORD S0 = (_rotr(a, 2)) ^ (_rotr(a, 13)) ^ (_rotr(a, 22));
		WORD S1 = (_rotr(e, 6)) ^ (_rotr(e, 11)) ^ (_rotr(e, 25));
		WORD ch = (e & f) ^ ((~e) & g);
		WORD maj = (a & b) ^ (a & c) ^ (b & c);
		WORD temp1 = h + S1 + ch + k_dev[i] + w[N_THRD_PER_BLK * i];
		WORD temp2 = S0 + maj;
		
		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}


	// ctx->h[0] = a + 0x6a09e667;
	// ctx->h[1] = b + 0xbb67ae85;
	// ctx->h[2] = c + 0x3c6ef372;
	// ctx->h[3] = d + 0xa54ff53a;
	// ctx->h[4] = e + 0x510e527f;
	// ctx->h[5] = f + 0x9b05688c;
	// ctx->h[6] = g + 0x1f83d9ab;
	// ctx->h[7] = h + 0x5be0cd19;


	((WORD *)&msg[N_THRD_PER_BLK * 0])[0] = a + 0x6a09e667;
	((WORD *)&msg[N_THRD_PER_BLK * 1])[0] = b + 0xbb67ae85;
	((WORD *)&msg[N_THRD_PER_BLK * 2])[0] = c + 0x3c6ef372;
	((WORD *)&msg[N_THRD_PER_BLK * 3])[0] = d + 0xa54ff53a;
	((WORD *)&msg[N_THRD_PER_BLK * 4])[0] = e + 0x510e527f;
	((WORD *)&msg[N_THRD_PER_BLK * 5])[0] = f + 0x9b05688c;
	((WORD *)&msg[N_THRD_PER_BLK * 6])[0] = g + 0x1f83d9ab;
	((WORD *)&msg[N_THRD_PER_BLK * 7])[0] = h + 0x5be0cd19;
    

    // ########################################


	// for(i = 0; i < 32 ; i += 4)
	// {
    //     _swap(ctx->b[i], ctx->b[i+3]);
    //     _swap(ctx->b[i+1], ctx->b[i+2]);
	// }


	for(i = 0; i < 8 ; i += 1)
	{
       
        _swap(msg[N_THRD_PER_BLK * i].b[0], msg[N_THRD_PER_BLK * i].b[3]);
        _swap(msg[N_THRD_PER_BLK * i].b[1], msg[N_THRD_PER_BLK * i].b[2]);
        
	}

}








__global__ void nonceSearch(unsigned char *blockHeader, unsigned int *nonceValidDev)
{

    int gtid = blockIdx.x * blockDim.x + threadIdx.x;
    int tid = threadIdx.x;

    __shared__ byte_group_t sm[(40960 + 80 + 32 + 32) / 4];

    HashBlock *blk;

    if(tid < 20){
        ((WORD *)&sm[BASE_ADDR_RAW_BLKHDR])[tid] = ((WORD *)blockHeader)[tid];
    }

    __syncthreads();
    
    if(tid == 0){
       
        sha256_commonBlkhdr_dev((SHA256 *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA], (BYTE *)&sm[BASE_ADDR_RAW_BLKHDR]);


        blk = (HashBlock *)&sm[BASE_ADDR_RAW_BLKHDR];

        unsigned int exp = blk->nbits >> 24;
        unsigned int mant = blk->nbits & 0xffffff;
        
        unsigned int shift = 8 * (exp - 3);
        unsigned int sb = shift >> 3; 
        unsigned int rb = shift % 8; 
        
        for(int i=0;i<8;i++){
            ((WORD *)&sm[BASE_ADDR_TD])[i] = 0;
        }

        // sm[BASE_ADDR_TD + sb    ] = (mant << rb);      
        // sm[BASE_ADDR_TD + sb + 1] = (mant >> (8-rb));  
        // sm[BASE_ADDR_TD + sb + 2] = (mant >> (16-rb)); 
        // sm[BASE_ADDR_TD + sb + 3] = (mant >> (24-rb)); 


        ((BYTE *)&sm[BASE_ADDR_TD])[sb    ] = (mant << rb);      
        ((BYTE *)&sm[BASE_ADDR_TD])[sb + 1] = (mant >> (8-rb));  
        ((BYTE *)&sm[BASE_ADDR_TD])[sb + 2] = (mant >> (16-rb)); 
        ((BYTE *)&sm[BASE_ADDR_TD])[sb + 3] = (mant >> (24-rb));         

    }

    __syncthreads();

    // SHA256 sha256_ctx;
    unsigned int nonce;
    // BYTE tmp[32];
    
    for(nonce = gtid * N_TSK_PER_THRD; nonce < (gtid + 1) * N_TSK_PER_THRD; ++nonce) 
    {       
        
        // ((int4 *)(tmp))[0] = ((int4 *)(&sm[BASE_ADDR_BLKHDR_COMMON_SHA]))[0];
        // ((int4 *)(tmp))[1] = ((int4 *)(&sm[BASE_ADDR_BLKHDR_COMMON_SHA]))[1];
        
        sha256_stage1_dev(sm, nonce);

        // sha256_stage2_dev(&sha256_ctx, tmp, sm); // 32 bytes
        sha256_stage2_dev(sm); // 32 bytes
        
        
        // if(little_endian_bit_comparison_dev(sha256_ctx.b, (BYTE *)&sm[BASE_ADDR_TD]) < 0)  
        if(little_endian_bit_comparison_dev(&sm[BASE_ADDR_THRD_LOCAL_SM + threadIdx.x], 
                                (BYTE *)&sm[BASE_ADDR_TD]) < 0)  
        {
            *nonceValidDev = nonce;
            break;
        }
    }
}




void solve(FILE *fin, FILE *fout)
{

    // **** read data *****
    char version[9];
    char prevhash[65];
    char ntime[9];
    char nbits[9];
    int tx;
    char *raw_merkle_branch;
    char **merkle_branch;

    getline(version, 9, fin);   
    getline(prevhash, 65, fin); 
    getline(ntime, 9, fin);
    getline(nbits, 9, fin);
    fscanf(fin, "%d\n", &tx);

    raw_merkle_branch = new char [tx * 65];
    merkle_branch = new char *[tx];

    for(int i = 0; i < tx; ++i)
    {
        merkle_branch[i] = raw_merkle_branch + i * 65;
        getline(merkle_branch[i], 65, fin);
        merkle_branch[i][64] = '\0';
    }

    // **** calculate merkle root ****
    unsigned char merkle_root[32];
    


    auto start = high_resolution_clock::now();
    
    calc_merkle_root(merkle_root, tx, merkle_branch);

    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    cout<<"calc_merkle_root() time: "<<duration.count()<<" us"<<endl;



    HashBlock block;
    // printf("sizeof(block): %d\n", (int)sizeof(block));

    // convert to byte array in little-endian
    convert_string_to_little_endian_bytes((unsigned char *)&block.version, version, 8);
    convert_string_to_little_endian_bytes(block.prevhash,                  prevhash,    64);
    memcpy(block.merkle_root, merkle_root, 32);
    convert_string_to_little_endian_bytes((unsigned char *)&block.nbits,   nbits,     8);
    convert_string_to_little_endian_bytes((unsigned char *)&block.ntime,   ntime,     8);
    block.nonce = 0;


    unsigned char *blockHeaderDev;
    unsigned int *nonceValidDev;
    unsigned int nonceValidHost = 0;

    cudaMalloc(&blockHeaderDev, BLK_HDR_SIZE);
    cudaMemcpy(blockHeaderDev, (unsigned char*)&block,
                         BLK_HDR_SIZE, cudaMemcpyHostToDevice);

    cudaMalloc(&nonceValidDev, sizeof(int));
    cudaMemset(nonceValidDev, 0, sizeof(int));
    

    start = high_resolution_clock::now();

    // cudaFuncSetCacheConfig(nonceSearch, cudaFuncCachePreferL1);
    nonceSearch<<< N_BLK, N_THRD_PER_BLK >>> (blockHeaderDev, nonceValidDev); 
    
    cudaDeviceSynchronize();
    cudaMemcpy(&nonceValidHost, nonceValidDev, sizeof(int), cudaMemcpyDeviceToHost);

    // while(!nonceValidHost){
    //     cudaMemcpy(&nonceValidHost, nonceValidDev, sizeof(int), cudaMemcpyDeviceToHost);
    // }

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
    cout<<"nonceSearch() time: "<<duration.count()<<" us"<<endl;

    
    for(int i=0; i < 4; ++i)
    {
        fprintf(fout, "%02x", ((unsigned char *)&nonceValidHost)[i]);
    }
    fprintf(fout, "\n");

    


    delete[] merkle_branch;
    delete[] raw_merkle_branch;
}







int main(int argc, char **argv)
{
    // cudaDeviceSetCacheConfig(cudaFuncCachePreferL1);

    

    if (argc != 3) {
        fprintf(stderr, "usage: cuda_miner <in> <out>\n");
    }

    FILE *fin = fopen(argv[1], "r");
    FILE *fout = fopen(argv[2], "w");

    int totalblock;

    fscanf(fin, "%d\n", &totalblock);
    fprintf(fout, "%d\n", totalblock);

    for(int i=0; i < totalblock; ++i)
    {
        solve(fin, fout);
    }

    return 0;
}