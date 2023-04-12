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

#include "sha256.h"



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




// convert hex string to binary
//
// in: input string
// string_len: the length of the input string
//      '\0' is not included in string_len!!!
// out: output bytes array




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



int little_endian_bit_comparison(const unsigned char *a, const unsigned char *b, size_t byte_len)
{
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
    calc_merkle_root(merkle_root, tx, merkle_branch);


    HashBlock block;
    // printf("sizeof(block): %d\n", (int)sizeof(block));

    // convert to byte array in little-endian
    convert_string_to_little_endian_bytes((unsigned char *)&block.version, version, 8);
    convert_string_to_little_endian_bytes(block.prevhash,                  prevhash,    64);
    memcpy(block.merkle_root, merkle_root, 32);
    convert_string_to_little_endian_bytes((unsigned char *)&block.nbits,   nbits,     8);
    convert_string_to_little_endian_bytes((unsigned char *)&block.ntime,   ntime,     8);
    block.nonce = 0;
    
    
    // ********** calculate target value *********
    unsigned int exp = block.nbits >> 24;
    unsigned int mant = block.nbits & 0xffffff;
    unsigned char target_hex[32] = {};
    
    unsigned int shift = 8 * (exp - 3);
    unsigned int sb = shift / 8; 
    unsigned int rb = shift % 8; 
    

    target_hex[sb    ] = (mant << rb);      
    target_hex[sb + 1] = (mant >> (8-rb));  
    target_hex[sb + 2] = (mant >> (16-rb)); 
    target_hex[sb + 3] = (mant >> (24-rb)); 

    
    // SHA256 sha256_ctx;
    
    // for(block.nonce = 0x00000000; block.nonce <= 0xffffffff; ++block.nonce) 
    // {   
    //     double_sha256(&sha256_ctx, (unsigned char*)&block, sizeof(block));
 
    //     if(little_endian_bit_comparison(sha256_ctx.b, target_hex, 32) < 0)  
    //     {
    //         break;
    //     }
    // }

    unsigned long long nTasks = 1 << 32;
    unsigned int nTskPerThrd = 65536;
    unsigned int nThrd = nTasks / nTskPerThrd;
    unsigned int nThrdPerBlk = 512;

    unsigned char *blockHeader, *nonceValidDev;
    unsigned char nonceValidHost[32];

    cudaMalloc(&blockHeader, sizeof(block));
    cudaMemcpy(blockHeader, (unsigned char*)&block,
                         sizeof(block), cudaMemcpyHostToDevice);

    cudaMalloc(&nonceValidDev, 4 * sizeof(unsigned char));
    solve<<< nThrd / nThrdPerBlk, nThrdPerBlk>>>(blockHeader, nonceValidDev); 

    cudaDeviceSynchronize();

    cudaMemcpy(nonceValidHost, nonceValidDev, 
                    4 * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    

    for(int i=0; i < 4; ++i)
    {
        fprintf(fout, "%02x", ((unsigned char*)&nonceValidHost)[i]);
    }
    fprintf(fout, "\n");


    delete[] merkle_branch;
    delete[] raw_merkle_branch;
}





__global__ void solve(unsigned char *blockHeader, unsigned char *nonceValidDev)
{

    // BLK_HDR_SIZE

    int gtid = blockIDx.x * blockDim.x + threadIdx.x;
    int tid = threadIdx.x;

    __shared__ unsigned char sm_blkHdr[BLK_HDR_SIZE];

    HashBlock blk;
    unsigned char* ptr;
    ptr = ((unsigned char*)&blk);

    if(tid < BLK_HDR_SIZE){
        sm_blkHdr[tid] = blockHeader[tid];
    }

    __syncthreads();
    
    for(int i = 0; i < BLK_HDR_SIZE; i++){
        ptr[i] = sm_blkHdr[i];
    }
    

    SHA256 sha256_ctx;
    
    for(block.nonce = gtid * nTskPerThrd; \
                    block.nonce < (gtid + 1) * nTskPerThrd; ++block.nonce) 
    {   
        double_sha256(&sha256_ctx, (unsigned char*)&block, sizeof(block));
 
        if(little_endian_bit_comparison(sha256_ctx.b, target_hex, 32) < 0)  
        {
            break;
        }
    }

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

