/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SIZE 64

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	char plaintext[SIZE] = {0, };
	char ciphertext[SIZE] = {0, };
	// key = random key + root key 
	int key;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
	
	// Initialize op Memory
	memset(&op, 0, sizeof(op));

	// Setting parameter types for text transfer
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);

	

	// Encrypt "TEEencrypt -e"
	if (strcmp(argv[1], "-e") == 0){
		printf("========================Encryption========================\n");
		FILE *fp;
		// File open with read mode
		fp = fopen(argv[2], "r");
		if(fp == NULL){
			printf("Failed to open file!!!\n");
			exit(0);
		}

		// Read file and Save content in plaintext
		fread(plaintext, 1, SIZE, fp);
		fclose(fp);
		printf("Plaintext : %s\n", plaintext);

		// Setting Parameter on op's buffer,size and Initialize value for transfer with TA
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = SIZE;
		op.params[1].value.a = 0;
		
		// Transfer with TA for Encrypt
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

		// Set content for save
		memcpy(ciphertext, op.params[0].tmpref.buffer, SIZE);
		printf("Ciphertext : %s\n", ciphertext);

		// Save Ciphertext as a txt file
		fp = fopen("ciphertext.txt", "w");
		fputs(ciphertext, fp); // Use 'fputs' because this is string
		fclose(fp);
		// Save Key(random key + root key), File open with write mode
		fp = fopen("key.txt", "w");
		key = op.params[1].value.a;
		fprintf(fp, "%d", key); // Use 'fprintf' because this is int
		fclose(fp);
	}
	//Decrypt "TEEencrypt -d"
	else if (strcmp(argv[1], "-d") == 0){
		printf("========================Decryption========================\n");
		// Setting Parameter on op's buffer,size and Initialize value for transfer with TA
		op.params[0].tmpref.buffer = ciphertext;
		op.params[0].tmpref.size = SIZE;
		op.params[1].value.a = 0;

		FILE *fp;
		fp = fopen(argv[2], "r");
		if(fp == NULL){
			printf("Failed to open file!!!\n");
			exit(0);
		}
		// Read ciphertext (string)
		fread(ciphertext, 1, SIZE, fp);
		fclose(fp);
		printf("Ciphertext : %s\n", ciphertext);

		fp = fopen(argv[3], "r");
		if(fp == NULL){
			printf("Failed to open file!!!\n");
			exit(0);
		}
		// Read key (int)
		fscanf(fp, "%d", &key);
		fclose(fp); 
		// Set content for transfer
		memcpy(op.params[0].tmpref.buffer, ciphertext, SIZE);
		op.params[1].value.a = key;
	
		// Transfer with TA
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x", res);
		// Set Imported content
		memcpy(plaintext, op.params[0].tmpref.buffer, SIZE);
		printf("Plaintext : %s\n", plaintext);
		
		// Save plaintext
		fp = fopen("plaintext.txt", "w");
		fputs(plaintext, fp);
		fclose(fp);
	}
	else
		return 1;

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
