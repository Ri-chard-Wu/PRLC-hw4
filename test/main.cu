

#include <iostream>
#include <fstream>
#include <string>
#include <cstdio>
#include <cstring>
#include <cassert>

#include <png.h>
#include <zlib.h>

#include <cmath>
#include <cstdlib>

#define _rotl(v, s) ((v)<<(s) | (v)>>(32-(s)))
#define _rotr(v, s) ((v)>>(s) | (v)<<(32-(s)))

#define _swap(x, y) (((x)^=(y)), ((y)^=(x)), ((x)^=(y)))


typedef struct _block
{
    unsigned int version;
    unsigned char prevhash[32];
    unsigned char merkle_root[32];
    unsigned int ntime;
    unsigned int nbits;
    unsigned int nonce;
}HashBlock;


__device__ 
void f2(int *a){
    printf("f2()\n");
    a[1] = 22;

}

__device__ void f1(int *a){
    printf("f1()\n");
    a[0] = 12;
    f2(a);
}

__constant__ int k[3] = {23, 456, 77};

__global__ void kernel()
{

    printf("blockIDx.x: %d\n", blockIDx.x);

    // *b = 23111;


    // printf("kernel()\n");


    // int a[3];
    // f1(a);

    // printf("a[0]: %d\n", a[0]);
    // printf("a[1]: %d\n", a[1]);



    // char m[2];
    // memset(m, 1, sizeof(m));
    
    // for(int i=0;i<2;i++){
    //     printf("m[i]: %d\n", (int) m[i]);
    // }



    // int a=4, b=8;
    // _swap(a,b);
    // printf("a: %d, b: %d\n", a, b);


    // HashBlock blk;
    // blk.nonce = 0x00001000;
    // printf("nonce: %d\n", blk.nonce);

}




#define nTasks_exp 32
#define nTskPerThrd_exp 16
#define nThrd_exp (nTasks_exp - nTskPerThrd_exp)
#define nThrdPerBlk_exp 9   // 2^9 == 512.

#define nBlks (1 << (nThrd_exp - nThrdPerBlk_exp))
#define nThrdPerBlk (1 << (nThrdPerBlk_exp))

int main(int argc, char **argv)
{

    // printf("nBlks: %d\n", nBlks);

    // int *b_dev, b_host;

    // cudaMalloc(&b_dev, sizeof(int));

    // cudaMemset(b_dev, 0, sizeof(int));

    kernel<<<2, 5>>>(); 

    // cudaMemcpy(&b_host, b_dev, sizeof(int), cudaMemcpyDeviceToHost);

    // printf("b_host: %d\n", b_host);

    // printf("main()\n");
    cudaDeviceSynchronize();

    return 0;
}

