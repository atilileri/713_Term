#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <math.h>

#define MEM_PER_OP 32
typedef char mem_t;
const float F2_BASE = 1.02197;
const float F1_RAISE = 45.141;
const float F1_FACTOR = (3570.0 / 9999);
const unsigned int F3_FACTOR = 16;
const float F_PI = (const float)acos(-1);

//global variables for and function declerations for performance measurements
double PCFreq = 0.0;
__int64 CounterStart = 0;
void StartCounter();
double GetCounter();
void encryptDecrypt(mem_t *input, mem_t *output, mem_t *key, size_t operation_size);

int main(int argc, char *argv[]) {

	FILE *fpIn, *fpOutEnc, *fpOutDec, *fpKey;
	const size_t MEM_SIZE = sizeof(mem_t);
	mem_t key[MEM_PER_OP];
	mem_t in[MEM_PER_OP];
	mem_t outEnc[MEM_PER_OP];
	mem_t outDec[MEM_PER_OP];
	double duration = 0.0, start = 0.0, end = 0.0;

	printf("########## CPU Run ##########\n");

	fpIn = fopen("../io/input_clean_100M.bin", "rb");
	fpOutEnc = fopen("../io/outCPU_enc.bin", "wb");
	fpOutDec = fopen("../io/outCPU_dec.bin", "wb");
	fpKey = fopen("../io/key.txt", "rb");
	//start counter for performance mesaurements
	StartCounter(); 
	if (fpIn != NULL && fpKey != NULL)
	{
		printf("File Processing\n");
		size_t readKeyMemCount;
		size_t readFileMemCount;
		while(0 < (readFileMemCount = fread(in, MEM_SIZE, MEM_PER_OP, fpIn)))
		{
			//provide circular key
			readKeyMemCount = fread(key, MEM_SIZE, MEM_PER_OP, fpKey);
			if (MEM_PER_OP != readKeyMemCount)
			{
				fseek(fpKey, 0, SEEK_SET);
				readKeyMemCount += fread(&(key[readKeyMemCount]), MEM_SIZE, MEM_PER_OP - readKeyMemCount, fpKey);
			}

			//printf("Key: %.*s\n", readKeyMemCount, key);

			//printf("Read: %.*s\n", readFileMemCount, in);
			start = GetCounter();
			encryptDecrypt(in, outEnc, key, readFileMemCount);
			end = GetCounter();
			duration += (end - start);
			//printf("Encrypted: %.*s\n", readFileMemCount, outEnc);
			fwrite(outEnc, MEM_SIZE, readFileMemCount, fpOutEnc);

			start = GetCounter();
			encryptDecrypt(outEnc, outDec, key, readFileMemCount);
			end = GetCounter();
			duration += (end - start);
			//printf("Decrypted: %.*s\n", readFileMemCount, outDec);
			fwrite(outDec, MEM_SIZE, readFileMemCount, fpOutDec);
		}
	}
	else
	{
		printf("File Not Found\n");
	}
	printf("Duration of the run: %f milliseconds.\n", GetCounter());
	printf("Encrypt + Decrypt: %f milliseconds.\n", duration);
	printf("End\n");

	fclose(fpIn);
	fclose(fpOutEnc);
	fclose(fpOutDec);
	fclose(fpKey);
}

void encryptDecrypt(mem_t *input, mem_t *output, mem_t *key, size_t operation_size) {
	int i;
	for (i = 0; i < operation_size; i++) {
		mem_t cypher_key = (mem_t) abs( (int)( ( ( log(F1_FACTOR * pow(key[i]+1, F1_RAISE)) + pow(F2_BASE, key[i]+1) ) + (F3_FACTOR * sin( ((key[i] + 1) * F_PI) / 2 )) )/ 2 ) );
		output[i] = input[i] ^ cypher_key;
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