#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);

/*************************************************************
M A I N
**************************************************************/
int main (int argc, char* argv[])
{

 //create context for BIGNUM
   	BN_CTX *bn_ctx;
	bn_ctx = BN_CTX_new();
//1. Alice reads the message from the "Message.txt" file
unsigned int message_length;
unsigned char* message = Read_File(argv[1],&message_length);

//2. Alice reads the seed from the "Seed.txt" file which contains 32 Bytes of random characters
unsigned int seed_length;
unsigned char* seed = Read_File(argv[2],&seed_length);

//3. Alice uses SHA256() to hash see to get private key --> 	y = SHA256(seed)
unsigned char buffer[SHA256_DIGEST_LENGTH];
unsigned char* private_key = SHA256(seed, seed_length, buffer);

//4. Alice uses private key to obtain public key -->	Y = y*G

//create curve
EC_GROUP* G_group = EC_GROUP_new_by_curve_name(NID_secp192k1);

//create a group and point
//EC_GROUP* G_group = EC_KEY_get0_group(G);
//const EC_POINT* G = EC_GROUP_get0_generator(G_group);
EC_POINT* G = EC_POINT_new(G_group);

//convert private key to hex
unsigned char* private_hex = malloc(SHA256_DIGEST_LENGTH*2+1); //allocate twice the length of the signature plus 1 for the null character
Convert_to_Hex(private_hex, private_key, SHA256_DIGEST_LENGTH);	

//convert the private key to BIGNUM
BIGNUM* private_num = BN_new();
BN_hex2bn(&private_num, private_hex);

//multiplication
EC_POINT* public = EC_POINT_new(G_group);
//EC_POINT_mul(G_group, public, NULL, G, private_num, NULL); // public = point * private_num -- > Y = y*G
EC_POINT_mul(G_group, public, private_num, NULL, NULL, NULL);

//5. Alice writes Hex format to keys, into 2 separate files "SK_HEX.txt" and "PK_HEX.txt"
Write_File("SK_Hex.txt", private_hex);

//unsigned char* public_hex = EC_POINT_point2hex(G_group, public, POINT_CONVERSION_UNCOMPRESSED, NULL); 

unsigned char* public_hex = malloc(2*(EC_GROUP_get_degree(G_group)/8) + 1);
public_hex = EC_POINT_point2hex(G_group, public, POINT_CONVERSION_UNCOMPRESSED, NULL);

Write_File("PK_Hex.txt", public_hex);
Show_in_Hex("Public Key Hex: ", public_hex, strlen(public_hex));

//PART 2
//1. Alice concatenates the message and the private key m||y and hashes using SHA(256)
 
    //concatenate
    unsigned char concat[SHA256_DIGEST_LENGTH + message_length]; //private key is size sha_digest
    memcpy(concat, message, message_length);	//add message first
    memcpy(concat + message_length, private_key, SHA256_DIGEST_LENGTH);	//private key next

    //hash the concatenated string to get little r
    unsigned char buffer2[SHA256_DIGEST_LENGTH];
    unsigned char* hash = SHA256(concat, SHA256_DIGEST_LENGTH + message_length, buffer2);

//2. Alice performs scalar multiplication to get R = r * G

    unsigned char* hash_hex = malloc(SHA256_DIGEST_LENGTH*2+1);  //convert little r to hex
    Convert_to_Hex(hash_hex, hash, SHA256_DIGEST_LENGTH);
    
    //convert the hash to BIGNUM
    BIGNUM* hash_num = BN_new();	//from hex convert little r to BIGNUM type
    BN_hex2bn(&hash_num, hash_hex);	
    
    //multiplication 	R = r * G
    EC_POINT* R = EC_POINT_new(G_group);	//create new point to store result
    EC_POINT_mul(G_group, R, hash_num, NULL, NULL, NULL);	//multiply to get R
 
//3. Alice computes s = r - y * SHA256(m||R) mod q
    //SHA256(m||R)
    
    //1 Convert R to unsigned char

    //size_t point_length = EC_POINT_point2buf(G_group, R, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
    unsigned char* R_buff; //= (unsigned char*) malloc(point_length);
    size_t lengthy = EC_POINT_point2buf(G_group, R, POINT_CONVERSION_UNCOMPRESSED, &R_buff, NULL);
    
    printf("Concatenated message: \n");
    
    //1a. convert R to hex
    unsigned char* R_hex = EC_POINT_point2hex(G_group, R, POINT_CONVERSION_UNCOMPRESSED, NULL);
    unsigned int R_buff_length = lengthy;

    //1b. Concatenate m||R
    unsigned char concat2[R_buff_length + message_length];
    memcpy(concat2, message, message_length);
    memcpy(concat2 + message_length, R_buff, R_buff_length);
    
    unsigned char buffer3[SHA256_DIGEST_LENGTH];
    unsigned char* hash2 = SHA256(concat2, R_buff_length + message_length, buffer3);
 
    //3a. get SHA256(m||R) into BIGNUM format
    //convert unsigned char to hex and then convert the hex to BIGNUM
    unsigned char* hash2_hex = malloc(SHA256_DIGEST_LENGTH*2+1); 
    Convert_to_Hex(hash2_hex, hash2, SHA256_DIGEST_LENGTH);
    BIGNUM* hash2_num = BN_new();
    BN_hex2bn(&hash2_num, hash2_hex);
    
    printf("Is step 3 working?\n"); 
    
    //3b. Convert q to BIGNUM 
      

     //2. get q
     BIGNUM* bn_q = BN_new();
     EC_GROUP_get_order(G_group, bn_q, bn_ctx);
    
    printf("Does this work \n");

    BIGNUM *s_mid = BN_new();
    
    //3c. perform y* SHA256(m||R) mod q
    //r = a*b mod m

    //int BN_mod_mul(BIGNUM *r, BIGNUM*a, BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
    BN_mod_mul(s_mid, private_num, hash2_num, bn_q, bn_ctx);
    printf("How about the modular multiplication \n");
     BIGNUM *s = BN_new();
     
    //r = a - b mod m
    //int BN_mod_sub(BIGNUM *r, BIGNUM*a, BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
    BN_mod_sub(s, hash_num, s_mid, bn_q, bn_ctx);
    printf("How about the modular subtraction \n");
    
    //4. Write R and s to files 
    unsigned char* s_hex = BN_bn2hex(s);
    Write_File("s_Hex.txt",s_hex);
     Write_File("R_Hex.txt",R_hex); // part of 4
 
//free the pointers
free(private_hex);
free(public_hex);
free(hash_hex);
free(hash2_hex);
free(R_hex);
    
BN_free(private_num);
BN_free(s);
BN_free(hash_num);
BN_free(hash2_num);
BN_free(bn_q);
BN_free(s_mid);

EC_POINT_free(public);
//EC_KEY_free(G);

return 0;

}


/*============================
        Read from File
==============================*/
unsigned char* Read_File (char fileName[], int *fileLen)
{
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
}

/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char input[]){
  FILE *pFile;
  pFile = fopen(fileName,"w");
  if (pFile == NULL){
    printf("Error opening file. \n");
    exit(0);
  }
  fputs(input, pFile);
  fclose(pFile);
}
/*============================
        Showing in Hex 
==============================*/
void Show_in_Hex(char name[], unsigned char hex[], int hexlen)
{
	printf("%s: ", name);
	for (int i = 0 ; i < hexlen ; i++)
   		printf("%02x", hex[i]);
	printf("\n");
}

/*============================
        Convert to Hex 
==============================*/
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    //printf("Hex format: %s\n", output);  //remove later
}

