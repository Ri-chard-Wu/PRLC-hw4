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

// #define N_BLK (1 << (N_THRD_EXP - N_THRD_PER_BLK_EXP)) // 2048 (2560 SM's)
// #define N_THRD_PER_BLK (1 << (N_THRD_PER_BLK_EXP)) // 128
// #define N_TSK_PER_THRD (1 << (N_TSK_PER_THRD_EXP)) // 16384

// 24 sec
#define N_BLK 2048
#define N_THRD_PER_BLK 64
#define N_TSK_PER_THRD 32768

// #define N_BLK 2560
// #define N_THRD_PER_BLK 64
// #define N_TSK_PER_THRD 26215


#define SIZE_TOTAL_LSM (N_THRD_PER_BLK * 256)
#define BASE_ADDR_RAW_BLKHDR (SIZE_TOTAL_LSM >> 2)
#define BASE_ADDR_BLKHDR_COMMON_SHA ((SIZE_TOTAL_LSM + 80) >> 2)
#define BASE_ADDR_TD ((SIZE_TOTAL_LSM + 112) >> 2)
#define BASE_ADDR_k ((SIZE_TOTAL_LSM + 144) >> 2)
#define BASE_ADDR_w ((SIZE_TOTAL_LSM + 400) >> 2)

#define BASE_ADDR_THRD_LOCAL_SM 0


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



// // print out binary array (from highest value) in the hex format
// void print_hex(unsigned char* hex, size_t len)
// {
//     for(int i=0;i<len;++i)
//     {
//         printf("%02x", hex[i]);
//     }
// }



__device__ void print_hex(unsigned char* hex, size_t n_bytes)
{
    printf("0x");
    for(int i=n_bytes-1;i>=0;i--)
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
    for(int i = 7; i >= 0; --i)
    {
        for(int j = 0; j <= 3; ++j){
            
            if(a[N_THRD_PER_BLK * i].b[j] < b[4 * i + 3 - j])
                return -1;
            else if(a[N_THRD_PER_BLK * i].b[j] > b[4 * i + 3 - j])
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
void compute_w(byte_group_t *sm){
    
    WORD i;

    byte_group_t *msg = &sm[BASE_ADDR_THRD_LOCAL_SM + threadIdx.x];


    #pragma unroll
    for(int i=0; i < 16; i++){
        ((WORD *)&msg[N_THRD_PER_BLK * i])[0] = 0;
    }

    WORD *w = (WORD *)&sm[BASE_ADDR_w];


    // ((WORD *)(&msg[N_THRD_PER_BLK * 3]))[0] = nonce;


    #pragma unroll
	for(i=0; i < 3; ++i) 
	{
        ((WORD *)&msg[N_THRD_PER_BLK * i])[0] = \
                    ((WORD *)&sm[BASE_ADDR_RAW_BLKHDR])[i + 16];
	}

  
    msg[N_THRD_PER_BLK * 4].b[0] = 0x80;  

    msg[N_THRD_PER_BLK * 15].b[3] = 640;  
    msg[N_THRD_PER_BLK * 15].b[2] = 2;  



    #pragma unroll
	for(i=0; i < 5; ++i)
	{
		w[i] = (msg[N_THRD_PER_BLK * i].b[0]<<24) | \
                                (msg[N_THRD_PER_BLK * i].b[1]<<16)| \
                                (msg[N_THRD_PER_BLK * i].b[2]<<8) | \
                                (msg[N_THRD_PER_BLK * i].b[3]);
	}




    #pragma unroll
	for(; i < 15; ++i)
	{
		w[i] = 0;
	}

    w[i] = (msg[N_THRD_PER_BLK * i].b[0]<<24) | \
                            (msg[N_THRD_PER_BLK * i].b[1]<<16)| \
                            (msg[N_THRD_PER_BLK * i].b[2]<<8) | \
                            (msg[N_THRD_PER_BLK * i].b[3]);
}



__device__ 
void sha256_stage1_dev(byte_group_t *sm, unsigned int nonce){

	WORD i;
    WORD a, b, c, d, e, f, g, h, t1, t2;

    WORD *k = (WORD *)&sm[BASE_ADDR_k];

    WORD *w = (WORD *)&sm[BASE_ADDR_THRD_LOCAL_SM + threadIdx.x];

    #pragma unroll
    for(i=0; i<16; i++) w[N_THRD_PER_BLK * i] = ((WORD *)&sm[BASE_ADDR_w])[i];
    w[N_THRD_PER_BLK * 3] = nonce;

    // printf("%d -> %d\n", nonce, (_rotr(nonce, 7)) ^ (_rotr(nonce, 18)) ^ (nonce >> 3));



    int gtid = blockIdx.x * blockDim.x + threadIdx.x;


    // ~ 2300 cycles
    #pragma unroll
	for( i = 16; i < 64; ++i)
	{

        // 16 <- 0, 1, 9, 14 
        // 17 <- 1, 2, 10, 15
        // 18* <- 2, 3*, 11, 16
        // 19* <- 3*, 4, 12, 17 
        // 20* <- 4, 5, 13, 18*
        // 21* <- 5, 6, 14, 19*
        // 22* <- 6, 7, 15, 20*
        // 23* <- 7, 8, 16, 21*
        // 24* <- 8, 9, 17, 22*
        // 25* <- 9, 10, 18*, 23*

        c = w[N_THRD_PER_BLK * (i-16)];
        a = w[N_THRD_PER_BLK * (i-15)];
        d = w[N_THRD_PER_BLK * (i-7)];
        b = w[N_THRD_PER_BLK * (i-2)];
        
		WORD s0 = (_rotr(a, 7)) ^ (_rotr(a, 18)) ^ (a >> 3);
		WORD s1 = (_rotr(b, 17)) ^ (_rotr(b, 19)) ^ (b >> 10);

		w[N_THRD_PER_BLK * i] = c + s0 + d + s1;     
	}




	a = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[0];
	b = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[1];
	c = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[2];
	d = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[3];
	e = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[4];
	f = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[5];
	g = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[6];
	h = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[7];

    SHA256_COMPRESS_8X

	w[N_THRD_PER_BLK * 0] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[0] + a;
	w[N_THRD_PER_BLK * 1] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[1] + b;
	w[N_THRD_PER_BLK * 2] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[2] + c;
	w[N_THRD_PER_BLK * 3] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[3] + d;
	w[N_THRD_PER_BLK * 4] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[4] + e;
	w[N_THRD_PER_BLK * 5] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[5] + f;
	w[N_THRD_PER_BLK * 6] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[6] + g;
	w[N_THRD_PER_BLK * 7] = ((WORD *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA])[7] + h;
    

}









__device__ 
void sha256_stage2_dev(byte_group_t *sm){
	
	WORD i;
    WORD a, b, c, d, e, f, g, h, t1, t2;	

    WORD *k = (WORD *)&sm[BASE_ADDR_k];

    WORD *w = (WORD *)&sm[BASE_ADDR_THRD_LOCAL_SM + threadIdx.x];
    
    w[N_THRD_PER_BLK * 8] = 0x80000000;  
    w[N_THRD_PER_BLK * 15] = 0x00000100;  

    #pragma unroll
	for(i = 9; i < 15; ++i) w[N_THRD_PER_BLK * i] = 0;

    #pragma unroll
	for( i = 16; i < 64; ++i)
	{
        c = w[N_THRD_PER_BLK * (i-16)];
        a = w[N_THRD_PER_BLK * (i-15)];
        d = w[N_THRD_PER_BLK * (i-7)];
        b = w[N_THRD_PER_BLK * (i-2)];

		WORD s0 = (_rotr(a, 7)) ^ (_rotr(a, 18)) ^  (a >> 3);
		WORD s1 = (_rotr(b, 17)) ^ (_rotr(b, 19)) ^ (b >> 10);

		w[N_THRD_PER_BLK * i] = c + s0 + d + s1;
	}


	a = 0x6a09e667;
	b = 0xbb67ae85;
	c = 0x3c6ef372;
	d = 0xa54ff53a;
	e = 0x510e527f;
	f = 0x9b05688c;
	g = 0x1f83d9ab;
	h = 0x5be0cd19;
    

    SHA256_COMPRESS_8X


	w[N_THRD_PER_BLK * 0] = a + 0x6a09e667;
	w[N_THRD_PER_BLK * 1] = b + 0xbb67ae85;
	w[N_THRD_PER_BLK * 2] = c + 0x3c6ef372;
	w[N_THRD_PER_BLK * 3] = d + 0xa54ff53a;
	w[N_THRD_PER_BLK * 4] = e + 0x510e527f;
	w[N_THRD_PER_BLK * 5] = f + 0x9b05688c;
	w[N_THRD_PER_BLK * 6] = g + 0x1f83d9ab;
	w[N_THRD_PER_BLK * 7] = h + 0x5be0cd19;
}




__device__ 
void compute_target_difficulty(byte_group_t *sm){
    
    HashBlock *blk = (HashBlock *)&sm[BASE_ADDR_RAW_BLKHDR];

    unsigned int exp = blk->nbits >> 24;
    unsigned int mant = blk->nbits & 0xffffff;
    
    unsigned int shift = 8 * (exp - 3);
    unsigned int sb = shift >> 3; 
    unsigned int rb = shift % 8; 
    
    for(int i=0;i<8;i++){
        ((WORD *)&sm[BASE_ADDR_TD])[i] = 0;
    }

    ((BYTE *)&sm[BASE_ADDR_TD])[sb    ] = (mant << rb);      
    ((BYTE *)&sm[BASE_ADDR_TD])[sb + 1] = (mant >> (8-rb));  
    ((BYTE *)&sm[BASE_ADDR_TD])[sb + 2] = (mant >> (16-rb)); 
    ((BYTE *)&sm[BASE_ADDR_TD])[sb + 3] = (mant >> (24-rb));    

}




__global__ void nonceSearch(unsigned char *blockHeader, unsigned int *nonceValidDev, int d, int n)
{

    int gtid = blockIdx.x * blockDim.x + threadIdx.x;
    int tid = threadIdx.x;
    int nlz_target;

    __shared__ byte_group_t sm[(SIZE_TOTAL_LSM + 80 + 32 + 32 + 256 + 256) / 4];

    
    // clock_t start_time = clock(); 
    // clock_t stop_time = clock();
    // int runtime = (int)(stop_time - start_time);
    // if(gtid == 0){
    //     printf("load sm dt: %d\n", runtime);
    // }


    if(tid < 20){
        ((WORD *)&sm[BASE_ADDR_RAW_BLKHDR])[tid] = ((WORD *)blockHeader)[tid];
    }

    if(tid < 64){
        ((WORD *)&sm[BASE_ADDR_k])[tid] = ((WORD *)k_dev)[tid];
    }


    __syncthreads();


    if(tid == 0){
        sha256_commonBlkhdr_dev((SHA256 *)&sm[BASE_ADDR_BLKHDR_COMMON_SHA], 
                                                (BYTE *)&sm[BASE_ADDR_RAW_BLKHDR]);
        compute_target_difficulty(sm);
        compute_w(sm);
    }

    __syncthreads();


    unsigned int nonce;
    

    for(nonce = gtid * N_TSK_PER_THRD + (N_TSK_PER_THRD / d) * n; 
        nonce < gtid * N_TSK_PER_THRD + (N_TSK_PER_THRD / d) * (n + 1); 
        ++nonce) 
    {       
        sha256_stage1_dev(sm, nonce);
        sha256_stage2_dev(sm); 

        if(little_endian_bit_comparison_dev(&sm[BASE_ADDR_THRD_LOCAL_SM + threadIdx.x], 
                                (BYTE *)&sm[BASE_ADDR_TD]) < 0)  
        {

            *nonceValidDev = (((BYTE *)&nonce)[0]<<24) | \
                                    (((BYTE *)&nonce)[1]<<16)| \
                                    (((BYTE *)&nonce)[2]<<8) | \
                                    (((BYTE *)&nonce)[3]);

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


    auto start = high_resolution_clock::now();

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

    unsigned char merkle_root[32];
    
    calc_merkle_root(merkle_root, tx, merkle_branch);

    HashBlock block;
  
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
    
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    cout<<"read tx & calc_merkle_root() time: "<<duration.count()/ 1000000.0 <<" sec"<<endl;


    int d = 16;

    for(int i=0;i<d;i++){

        nonceSearch<<< N_BLK, N_THRD_PER_BLK >>> (blockHeaderDev, nonceValidDev, d, i); 
        cudaDeviceSynchronize();
        cudaMemcpy(&nonceValidHost, nonceValidDev, sizeof(int), cudaMemcpyDeviceToHost);
        
        if(nonceValidHost) break;     
    }
    

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