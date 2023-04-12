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
#define N_TSK_PER_THRD_EXP 16
#define N_THRD_EXP (N_TSK_EXP - N_TSK_PER_THRD_EXP)
#define N_THRD_PER_BLK_EXP 9   // 2^9 == 512.

#define N_BLK (1 << (N_THRD_EXP - N_THRD_PER_BLK_EXP))
#define N_THRD_PER_BLK (1 << (N_THRD_PER_BLK_EXP))
#define N_TSK_PER_THRD (1 << (N_TSK_PER_THRD_EXP))







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
void sha256_dev(SHA256 *ctx, const BYTE *msg, size_t len){
	
	ctx->h[0] = 0x6a09e667;
	ctx->h[1] = 0xbb67ae85;
	ctx->h[2] = 0x3c6ef372;
	ctx->h[3] = 0xa54ff53a;
	ctx->h[4] = 0x510e527f;
	ctx->h[5] = 0x9b05688c;
	ctx->h[6] = 0x1f83d9ab;
	ctx->h[7] = 0x5be0cd19;
	
	WORD i, j;
	size_t remain = len % 64;
	size_t total_len = len - remain;

	for(i=0; i < total_len; i += 64) 
	{
		
		sha256_transform_dev(ctx, &msg[i]);
	}
	
	BYTE m[64] = {};
	for(i=total_len, j=0; i < len; ++i, ++j) 
	{
		m[j] = msg[i];
	}

	m[j++] = 0x80;  
	
	if(j > 56) // never true?
	{
		sha256_transform_dev(ctx, m);
		memset(m, 0, sizeof(m));
		printf("true\n");
	}
	
	unsigned long long L = len * 8;  
	m[63] = L;
	m[62] = L >> 8;
	m[61] = L >> 16;
	m[60] = L >> 24;
	m[59] = L >> 32;
	m[58] = L >> 40;
	m[57] = L >> 48;
	m[56] = L >> 56;
	sha256_transform_dev(ctx, m);
	
	for(i=0;i<32;i+=4)
	{
        _swap(ctx->b[i], ctx->b[i+3]);
        _swap(ctx->b[i+1], ctx->b[i+2]);
	}
}







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



__device__ 
int little_endian_bit_comparison_dev(const unsigned char *a, 
                                        const unsigned char *b, size_t byte_len){
    // compared from lowest bit
    for(int i = byte_len - 1; i >= 0; --i)
    {
        if(a[i] < b[i])
            return -1;
        else if(a[i] > b[i])
            return 1;
    }
    return 0;
}



void getline(char *str, size_t len, FILE *fp)
{

    int i=0;
    while( i<len && (str[i] = fgetc(fp)) != EOF && str[i++] != '\n');
    str[len-1] = '\0';
}



////////////////////////   Hash   ///////////////////////

// `len` == 64 (bytes) == two 256-bits number.
void double_sha256(SHA256 *sha256_ctx, unsigned char *bytes, size_t len)
{
    SHA256 tmp;

    // tmp = hash(list[i]+list[i+1]), i: 0 ~ txLen - 1, i += 2.
    sha256(&tmp, (BYTE*)bytes, len);   
    
    // list[j] = hash(tmp), j: 0 ~ txLen / 2 - 1, j += 1.    
    sha256(sha256_ctx, (BYTE*)&tmp, sizeof(tmp));
}




__device__ 
void double_sha256_dev(SHA256 *sha256_ctx, unsigned char *bytes, size_t len){
    SHA256 tmp;

    sha256_dev(&tmp, (BYTE*)bytes, len);   
    sha256_dev(sha256_ctx, (BYTE*)&tmp, sizeof(tmp));
}

////////////////////   Merkle Root   /////////////////////





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





__global__ void nonceSearch(unsigned char *blockHeader, unsigned int *nonceValidDev)
{

    int gtid = blockIdx.x * blockDim.x + threadIdx.x;
    int tid = threadIdx.x;

    __shared__ unsigned char sm_blkHdr[BLK_HDR_SIZE];

    HashBlock blk;
    unsigned char* ptr;
    ptr = ((unsigned char*)&blk);

    if(tid < BLK_HDR_SIZE){
        sm_blkHdr[tid] = blockHeader[tid];
    }

    __syncthreads();
    
    for(int i = 0; i < BLK_HDR_SIZE; i++){ // broadcast-type access to sm.
        ptr[i] = sm_blkHdr[i];
    }
    


    unsigned int exp = blk.nbits >> 24;
    unsigned int mant = blk.nbits & 0xffffff;
    unsigned char target_hex[32] = {};
    
    unsigned int shift = 8 * (exp - 3);
    unsigned int sb = shift / 8; 
    unsigned int rb = shift % 8; 
    
    target_hex[sb    ] = (mant << rb);      
    target_hex[sb + 1] = (mant >> (8-rb));  
    target_hex[sb + 2] = (mant >> (16-rb)); 
    target_hex[sb + 3] = (mant >> (24-rb)); 



    SHA256 sha256_ctx;
    
    for(blk.nonce = gtid * N_TSK_PER_THRD; \
                    blk.nonce < (gtid + 1) * N_TSK_PER_THRD; ++blk.nonce) 
    {   
        double_sha256_dev(&sha256_ctx, (unsigned char*)&blk, BLK_HDR_SIZE);
 
        if(little_endian_bit_comparison_dev(sha256_ctx.b, target_hex, 32) < 0)  
        {
            *nonceValidDev = blk.nonce;
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

    nonceSearch<<< N_BLK, N_THRD_PER_BLK >>> (blockHeaderDev, nonceValidDev); 

    while(!nonceValidHost){
        cudaMemcpy(&nonceValidHost, nonceValidDev, sizeof(int), cudaMemcpyDeviceToHost);
    }

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

