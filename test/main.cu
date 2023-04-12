

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

__global__ void kernel(int *b)
{

    // *b = 23111;

    printf("kernel()\n");


    int a[3];
    f1(a);

    printf("a[0]: %d\n", a[0]);
    printf("a[1]: %d\n", a[1]);



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






int main(int argc, char **argv)
{


    int *b_dev, b_host;

    cudaMalloc(&b_dev, sizeof(int));

    cudaMemset(b_dev, 0, sizeof(int));

    kernel<<<2, 5>>>(b_dev); 

    cudaMemcpy(&b_host, b_dev, sizeof(int), cudaMemcpyDeviceToHost);

    printf("b_host: %d\n", b_host);

    printf("main()\n");
    cudaDeviceSynchronize();

    return 0;
}

