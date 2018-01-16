#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <math.h>
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

#define SIZE_5K (1024 * 5)				// 5KB
#define SIZE_5K_ULL4 (SIZE_5K / 32)		// 5 KB / (sizeof(unsigned long long) * 4)
#define SIZE_10M (1024 * 1024 * 10)		// 10 MB	
#define SIZE_10M_ULL4 (SIZE_10M / 32)	// 10 MB / (sizeof(unsigned long long) * 4)
#define BLOCK_SIZE 1024

typedef char mem_t;
typedef ulonglong4 memUll4_t;

const float F2_BASE = (float) 1.02197;
const float F1_RAISE = (float) 45.141;
const float F1_FACTOR = (float)(3570.0 / 9999);
const unsigned int F3_FACTOR = 16;

//global variables for and function declerations for performance measurements
double PCFreq = 0.0;
__int64 CounterStart = 0;
void StartCounter();
double GetCounter();
__global__ void encryptDecrypt(mem_t *input, mem_t *output, mem_t *key, size_t readKeySizeInBytes, size_t readFileSizeInBytes, const float F2_BASE, const float F1_RAISE, const float F1_FACTOR, const unsigned int F3_FACTOR, const float F_PI);

int main(int argc, char *argv[])
{

	//printf("%d\n", sizeof(char));						// 1
	//printf("%d\n", sizeof(unsigned int));				// 4
	//printf("%d\n", sizeof(uint4));					// 16
	//printf("%d\n", sizeof(unsigned long long));		// 8
	//printf("%d\n", sizeof(unsigned long long int));	// 8
	//printf("%d\n", sizeof(ulonglong4));				// 32
	FILE *fpIn, *fpOutEnc, *fpOutDec, *fpKey;
	const size_t MEM_ULL4_SIZE = sizeof(memUll4_t);
	memUll4_t *key, *in, *outEnc, *outDec;
	mem_t *pSrc_Dev, *pKey_Dev, *pDstEnc_Dev, *pDstDec_Dev;
	double duration = 0.0, start = 0.0, end = 0.0;

	printf("########## CUDA Run ##########\n");

	fpIn = fopen("../io/input_clean.txt", "rb");
	fpOutEnc = fopen("../io/outCUDA_enc.txt", "wb");
	fpOutDec = fopen("../io/outCUDA_dec.txt", "wb");
	fpKey = fopen("../io/key.txt", "rb");
	//start counter for performance mesaurements
	StartCounter();
	if (fpIn != NULL && fpKey != NULL && fpOutEnc != NULL && fpOutDec != NULL)
	{
		printf("Read File\n");
		size_t readKeyMemCount;
		size_t readFileMemCount;

		key = (memUll4_t*)malloc(SIZE_5K);
		in = (memUll4_t*)malloc(SIZE_10M);
		
		if ( (0 < (readFileMemCount = fread(in, MEM_ULL4_SIZE, SIZE_10M_ULL4, fpIn))) && (0 < (readKeyMemCount = fread(key, MEM_ULL4_SIZE, SIZE_5K_ULL4, fpKey))))
		{
			//printf("%d\n", readFileMemCount); //249268 which is ~(7.6M / 32)
			//printf("%d\n", readKeyMemCount); //45 which is ~(1.4K / 32)
			size_t  readFileSizeInBytes = sizeof(memUll4_t) * readFileMemCount;
			size_t  readKeySizeInBytes = sizeof(memUll4_t) * readKeyMemCount;
			outEnc = (memUll4_t*)malloc(readFileSizeInBytes);
			outDec = (memUll4_t*)malloc(readFileSizeInBytes);
			
			cudaMalloc(&pSrc_Dev, readFileSizeInBytes);
			cudaMalloc(&pKey_Dev, readKeySizeInBytes);

			cudaMemcpy(pSrc_Dev, in, readFileSizeInBytes, cudaMemcpyHostToDevice);
			cudaMemcpy(pKey_Dev, key, readKeySizeInBytes, cudaMemcpyHostToDevice);

			dim3 dimGrid((unsigned int)(readFileSizeInBytes / BLOCK_SIZE) + 1);
			dim3 dimBlock(BLOCK_SIZE);

			cudaMalloc(&pDstEnc_Dev, readFileSizeInBytes);

			const float F_PI = (const float)acos(-1);
			start = GetCounter();
			encryptDecrypt<< <dimGrid, dimBlock >> >(pSrc_Dev, pDstEnc_Dev, pKey_Dev, readKeySizeInBytes, readFileSizeInBytes, F2_BASE ,F1_RAISE, F1_FACTOR, F3_FACTOR, F_PI);
			end = GetCounter();
			duration += (end - start);
			cudaMemcpy(outEnc, pDstEnc_Dev, readFileSizeInBytes, cudaMemcpyDeviceToHost);

			fwrite(outEnc, MEM_ULL4_SIZE, readFileMemCount, fpOutEnc);

			cudaMalloc(&pDstDec_Dev, readFileSizeInBytes);
			start = GetCounter();
			encryptDecrypt << <dimGrid, dimBlock >> >(pDstEnc_Dev, pDstDec_Dev, pKey_Dev, readKeySizeInBytes, readFileSizeInBytes, F2_BASE, F1_RAISE, F1_FACTOR, F3_FACTOR, F_PI);
			end = GetCounter();
			duration += (end - start);
			cudaMemcpy(outDec, pDstDec_Dev, readFileSizeInBytes, cudaMemcpyDeviceToHost);

			fwrite(outDec, MEM_ULL4_SIZE, readFileMemCount, fpOutDec);
		}
		else
		{
			printf("Read Error\n");
		}
	}
	else
	{
		printf("File Not Found\n");
	}
	printf("Duration of the run: %f milliseconds.\n", GetCounter());
	printf("Encrypt + Decrypt: %f milliseconds.\n", duration);
	printf("End\n");

	free(key);
	free(in);
	free(outEnc);
	free(outDec);
	cudaFree(pSrc_Dev);
	cudaFree(pKey_Dev);
	cudaFree(pDstEnc_Dev);
	cudaFree(pDstDec_Dev);
	fclose(fpIn);
	fclose(fpOutEnc);
	fclose(fpOutDec);
	fclose(fpKey);

}

__global__ void encryptDecrypt(mem_t *input, mem_t *output, mem_t *key, size_t readKeySizeInBytes, size_t readFileSizeInBytes, const float F2_BASE, const float F1_RAISE, const float F1_FACTOR, const unsigned int F3_FACTOR, const float F_PI)
{
	size_t memberIndex = (blockIdx.x * blockDim.x) + threadIdx.x;
	if (readFileSizeInBytes > memberIndex)
	{
		int keyIndex = memberIndex % readKeySizeInBytes;
	
		mem_t cypher_key = (mem_t)abs((int)(((logf(F1_FACTOR * powf(key[keyIndex] + 1, F1_RAISE)) + powf(F2_BASE, key[keyIndex] + 1)) + (F3_FACTOR * sinf(((key[keyIndex] + 1) * F_PI) / 2))) / 2));

		output[memberIndex] = input[memberIndex] ^ cypher_key;
	}
}

void StartCounter()
{
	LARGE_INTEGER li;
	if (!QueryPerformanceFrequency(&li))
		printf("QueryPerformanceFrequency failed!\n");

	PCFreq = double(li.QuadPart) / 1000.0;

	QueryPerformanceCounter(&li);
	CounterStart = li.QuadPart;
}

double GetCounter()
{
	LARGE_INTEGER li;
	QueryPerformanceCounter(&li);
	return double(li.QuadPart - CounterStart) / PCFreq;
}