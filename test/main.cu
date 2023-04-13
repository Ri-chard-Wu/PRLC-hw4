

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

#include <chrono>

using namespace std::chrono;
using namespace std;

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

__device__ void f1(int *sm){
    printf("f1()\n");
    printf("sm[0]: %d\n", sm[0]);
    // a[0] = 12;
    // f2(a);
}









// __global__ void kernel()
// {
//     // __shared__ double sm[20 * 5];


//     double a[10], sum;
    
//     sum = 0;

//     for(int i=0;i<10;i++){
//         a[i] = i * (blockIdx.x + 1) * (threadIdx.x + 1);
//         for(int j=0;j<10000000;j++){
//             a[i] *= 1.00000001; 
//         }
//         sum += a[i];
//     }

    
//     printf("[%d, %d]: %f\n", blockIdx.x, threadIdx.x, sum);
    

// }










__global__ void kernel()
{
    __shared__ double sm[10*5]; // 3.2 kB
    
    int tid = threadIdx.x;


    // double a[10], sum;
    
    double sum = 0;

    for(int i=0;i<10;i++){
        sm[10 * tid + i] = i * (blockIdx.x + 1) * (threadIdx.x + 1);
        for(int j=0;j<10000000;j++){
            sm[10 * tid + i] *= 1.00000001; 
        }
        sum += sm[10 * tid + i];
    }

    
    printf("[%d, %d]: %f\n", blockIdx.x, threadIdx.x, sum);
    

}





int main(int argc, char **argv)
{
    int a = 0x0123f7aa;

    unsigned char *ptr = (unsigned char *)&a;

    printf("ptr[0]: %d\n", ptr[0]);
    printf("ptr[1]: %d\n", ptr[1]);
    printf("ptr[2]: %d\n", ptr[2]);
    printf("ptr[3]: %d\n", ptr[3]);





    // auto start = high_resolution_clock::now();
    
    // kernel<<<2, 5>>>(); 

    // auto stop = high_resolution_clock::now();
    // auto duration = duration_cast<microseconds>(stop - start);
    // cout<<"kernel() time: "<<duration.count()<<" us"<<endl;


    // cudaMemcpy(&b_host, b_dev, sizeof(int), cudaMemcpyDeviceToHost);

    // printf("b_host: %d\n", b_host);

    // printf("main()\n");
    cudaDeviceSynchronize();

    return 0;
}

