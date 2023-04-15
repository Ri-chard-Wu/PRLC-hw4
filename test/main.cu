

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






// ============== Non-strided ===================


// #define N_THRD 128
// #define SIZE_LSM 320

// __global__ void kernel()
// {
    
//     int gtid = blockIdx.x * blockDim.x + threadIdx.x;
//     int tid = threadIdx.x;

//     __shared__ unsigned char sm[SIZE_LSM * N_THRD]; // 40960


//     unsigned char *lsm = &sm[SIZE_LSM * tid];

//     for(int i=0; i < SIZE_LSM; i++){
//         lsm[i] = tid + i;
//     }


//     double value;
//     for(int i=0; i < SIZE_LSM; i++){

//         value = lsm[i] + lsm[i];
//         lsm[i] = value;

//     }

//     int sum = 0;
//     for(int i=0; i < SIZE_LSM; i++){
//         sum += lsm[i];
//     }

//     printf("[%d, %d] sum: %d\n", blockIdx.x, threadIdx.x, sum);
// }







// // ============== Stride size: 1 byte ===================

// #define N_THRD 128
// #define SIZE_LSM 320

// __global__ void kernel()
// {
    
//     int gtid = blockIdx.x * blockDim.x + threadIdx.x;
//     int tid = threadIdx.x;

//     __shared__ unsigned char sm[SIZE_LSM * N_THRD]; // 40960


//     unsigned char *lsm = &sm[tid];
//     int sum = 0;

//     for(int i=0; i < SIZE_LSM; i++){
//         lsm[N_THRD * i] = tid + i ;
//     }


 
//     for(int i=0; i < SIZE_LSM; i++){

//         for(int j=0;j<500000;j++){
//             lsm[N_THRD * i] = lsm[N_THRD * i] * tid + i;
//         }

//     }

    
//     for(int i=0; i < SIZE_LSM; i++){
//         sum += lsm[N_THRD * i];
//     }

//     printf("[%d, %d] sum: %d\n", blockIdx.x, threadIdx.x, sum);
// }









// // ============== non-strided: 1 word ===================

// #define N_THRD 128
// #define SIZE_LSM 320

// __global__ void kernel()
// {
    
//     int gtid = blockIdx.x * blockDim.x + threadIdx.x;
//     int tid = threadIdx.x;

//     __shared__ unsigned int sm[(SIZE_LSM / 4) * N_THRD]; // 40960


//     unsigned int *lsm = &sm[(SIZE_LSM / 4) * tid];


//     for(int i=0; i < SIZE_LSM / 4; i++){
//         for(int j=0;j<4;j++){
//             ((unsigned char *)&lsm[i])[j] = tid + (4 * i + j);
//         }
//     }


//     for(int i=0; i < SIZE_LSM / 4; i++){
//         for(int j=0;j<4;j++){
//             for(int k=0;k<500000;k++){
//                 ((unsigned char *)&lsm[i])[j] = \
//                             ((unsigned char *)&lsm[i])[j] * tid + (4 * i + j);
//             }
//         }
//     }



//     int sum = 0;
//     for(int i=0; i < SIZE_LSM / 4; i++){
//         for(int j=0;j<4;j++){
//            sum += ((unsigned char *)&lsm[i])[j];
//         }
//     }


//     printf("[%d, %d] sum: %d\n", blockIdx.x, threadIdx.x, sum);
// }





// ============== Stride size: 1 word ===================

#define N_THRD 128
#define SIZE_LSM 320

__global__ void kernel()
{
    
    int gtid = blockIdx.x * blockDim.x + threadIdx.x;
    int tid = threadIdx.x;

    __shared__ unsigned int sm[(SIZE_LSM / 4) * N_THRD]; // 40960


    unsigned int *lsm = &sm[tid];


    for(int i=0; i < SIZE_LSM / 4; i++){
        for(int j=0;j<4;j++){
            ((unsigned char *)&lsm[N_THRD * i])[j] = tid + (4 * i + j);
        }
    }


    for(int i=0; i < SIZE_LSM / 4; i++){
        for(int j=0;j<4;j++){
            for(int k=0;k<500000;k++){
                ((unsigned char *)&lsm[N_THRD * i])[j] = \
                            ((unsigned char *)&lsm[N_THRD * i])[j] * tid + (4 * i + j);
            }
        }
    }



    int sum = 0;
    for(int i=0; i < SIZE_LSM / 4; i++){
        for(int j=0;j<4;j++){
           sum += ((unsigned char *)&lsm[N_THRD * i])[j];
        }
    }


    printf("[%d, %d] sum: %d\n", blockIdx.x, threadIdx.x, sum);
}






void print_hex(unsigned char* hex, size_t n_bytes)
{
    printf("0x");
    for(int i=n_bytes-1;i>=0;i--)
    {
        printf("%02x", hex[i]);
    }
    
}

#include <algorithm>
#include <vector>

int main(int argc, char **argv)
{
    // int nums[9] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    vector<int> vec;
    for(int i=0;i<9;i++){
        vec.push_back(i);
    }

    std::random_shuffle(vec.begin(), vec.end());

    for(int i=0;i<9;i++){
        printf("%d\n", vec[i]);
    }


    // unsigned int a = 0x34f6a4c5;

    // print_hex((unsigned char *)&a, 4);

    // auto start = high_resolution_clock::now();
    
    // kernel<<<1, N_THRD>>>(); 
    // cudaDeviceSynchronize();

    // auto stop = high_resolution_clock::now();
    // auto duration = duration_cast<microseconds>(stop - start);
    // cout<<" time: "<<duration.count() / 1000<<" ms"<<endl;

    return 0;
}

