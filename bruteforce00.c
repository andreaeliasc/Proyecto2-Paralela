#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <rpc/des_crypt.h>


#define MAXC 1024
#define KEY  2310089
#define DEFAULT_FILENAME "message.txt"


void decrypt(long key, char *ciph, int len){
	long k = 0;

	for(int i=0; i<8; ++i){
		key <<= 1;
		k += (key & (0xFE << i*8));
	}

	des_setparity((char *)&k);
	ecb_crypt((char *)&k, (char *) ciph, 16, DES_DECRYPT);
}

void _encrypt(long key, char *ciph, int len){
	long k = 0;

	for(int i=0; i<8; ++i){
		key <<= 1;
		k += (key & (0xFE << i*8));
	}

	des_setparity((char *)&k);
	ecb_crypt((char *)&k, (char *) ciph, 16, DES_ENCRYPT);
}


char search[] = " lectus ";


int tryKey(long key, char *ciph, int len){
	char temp[len+1];
	memcpy(temp, ciph, len);
	temp[len]=0;

	decrypt(key, temp, len);

	return strstr((char *)temp, search) != NULL;
}


int main(int argc, char *argv[]){
	double t1, t2;
	int N, id;
	long upper = (1L << 56);
	long mylower, myupper;

	MPI_Status st;
	MPI_Request req;

	FILE *file;
	char *buffer = malloc(sizeof(char) * MAXC);
	char *cipher = malloc(sizeof(char) * MAXC);

	file = fopen(DEFAULT_FILENAME, "r");
	if (file == NULL) return -1;

	int i = 0;
	while((buffer[i] = fgetc(file)) != EOF){
		cipher[i] = buffer[i];
		i++;

		if (i + 1 > MAXC) break;
	}

	cipher[i] = '\0';

	free(buffer);

	int ciphlen = strlen(cipher);

	_encrypt(KEY, cipher, ciphlen);

	MPI_Comm comm = MPI_COMM_WORLD;

	MPI_Init(NULL, NULL);
	t1 = MPI_Wtime();

	MPI_Comm_size(comm, &N);
	MPI_Comm_rank(comm, &id);

	long range_per_node = upper / N;

	mylower = range_per_node * id;
	myupper = range_per_node * (id + 1) - 1;

	if(id == N - 1){
		myupper = upper;
	}

	long found = 0;
	int ready = 0;

	MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

	for(long i = mylower; i<myupper; ++i){
		MPI_Test(&req, &ready, MPI_STATUS_IGNORE);

		if(ready) break;

		if(tryKey(i, (char *)cipher, ciphlen)){
			found = i;
			for(int node = 0; node < N; node++){
				MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
			}
			break;
		}
	}

	if(id==0){
		MPI_Wait(&req, &st);
		decrypt(found, (char *)cipher, ciphlen);
		t2 = MPI_Wtime();
		printf("Key encountered:\n%li,\nText:\n%s\n", found, cipher);
		printf("Elapsed time is %f seconds\n", t2 - t1);
	}

	free(cipher);

	MPI_Finalize();
}
