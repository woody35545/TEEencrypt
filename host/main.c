#include <err.h>
#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include <TEEencrypt_ta.h>

FILE *fs; // input 받을 file 포인터
char option[10]; /* option 에 관한 argument를 할당할 char[] */
char context_file_name[100]; /* 입력받을 파일의 이름을 저장할 char[] */ 
char context_input_buffer[100]; /* 입력받을 파일의 데이터를 담을 버퍼 */
int len = 100;

TEEC_Result res;
TEEC_Context ctx;
TEEC_Session sess;
TEEC_Operation op;
TEEC_UUID uuid = TA_TEEencrypt_UUID;
uint32_t err_origin;


void send_encrypt_request(void){
	char ciphertext [100] = {0,}; 
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = context_input_buffer;
	op.params[0].tmpref.size = len;

	fs = fopen(context_file_name,"r"); // input 파일 읽어옴
	fgets(context_input_buffer, sizeof(context_input_buffer),fs);

	printf("========================Encryption========================\n");
	memcpy(op.params[0].tmpref.buffer, context_input_buffer, len);

	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENCRYPT, &op,&err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",res, err_origin);

	memcpy(ciphertext, op.params[0].tmpref.buffer, len);
	printf("Ciphertext : %s\n", ciphertext);
	fclose(fs);
}

void send_decrypt_request(void){
	char plaintext [100] = {0,};

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = context_input_buffer;
	op.params[0].tmpref.size = len;

	
	fs = fopen(context_file_name,"r"); // input 파일 읽어옴
	fgets(context_input_buffer, sizeof(context_input_buffer),fs);
	
	printf("========================Decryption========================\n");
	memcpy(op.params[0].tmpref.buffer, context_input_buffer, len);

	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DECRYPT, &op,&err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",res, err_origin);

	memcpy(plaintext, op.params[0].tmpref.buffer, len);
	printf("Plaintext : %s\n", plaintext);
	fclose(fs);
}

int main(int argc, char *argv[]) // Option을 인자로 받기위해 파라미터로 Argument들을 받도록 함.
{
	
	context_input_buffer = {0,};
	
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);


	/* Argument 초기화 */
	if(argc >= 3){
		// 확인완료
		strcpy(option, argv[1]); //  argv[1] 위치가 option
		strcpy(context_file_name, argv[2]); // argv[2] 위치가 파일 이름
	} 
	if(strcmp(option, "-e") == 0){

		printf("Encrypt option\n");
		// TA 쪽에 Encrypt Request 해야하는 부분
	 	send_encrypt_request();
	}

	else if(strcmp(option, "-d") == 0){
		printf("Decrypt option\n");
		// TA 쪽에 Decrypt Request 해야하는 부분
		send_decrypt_request();
	}

	else{
		printf("Warning: Invalid Command\n") ;	
	}
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
