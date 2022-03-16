// opensslRsa.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
extern "C"
{
#include <openssl/applink.c>
};

#define PRIKEY "C:\\Users\\Method.jiao-PC\\Desktop\\opensslRsa\\x64\\Debug\\prikey.pem"
#define PUBKEY "C:\\Users\\Method.jiao-PC\\Desktop\\opensslRsa\\x64\\Debug\\pubkey.pem"
#define BUFFSIZE 4096
//公钥加密
char* pubKeyEncrypt(const char* str, const char* pubkey_path)
{
    RSA* rsa = NULL;
    FILE* fp = NULL;
    char* en = NULL;
    int len = 0;
    int rsa_len = 0;

    if ((fp = fopen(pubkey_path, "r")) == NULL) {
        return NULL;
    }

    /* 读取公钥PEM，PUBKEY格式PEM使用PEM_read_RSA_PUBKEY函数 */
    if ((rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL)) == NULL) {
        return NULL;
    }

    RSA_print_fp(stdout, rsa, 0);

    len = strlen(str);
    rsa_len = RSA_size(rsa);

    en = (char*)malloc(rsa_len + 1);
    memset(en, 0, rsa_len + 1);

    if (RSA_public_encrypt(rsa_len, (unsigned char*)str, (unsigned char*)en, rsa, RSA_NO_PADDING) < 0) {
        return NULL;
    }

    RSA_free(rsa);
    fclose(fp);

    return en;
}
//私钥加密
char* priKeyEncrypt(const char* str, const char* prikey_path)
{
	RSA* rsa = NULL;
	FILE* fp = NULL;
	char* en = NULL;
	int len = 0;
	int rsa_len = 0;

	if ((fp = fopen(prikey_path, "r")) == NULL) {
		return NULL;
	}


	if ((rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL) {
		return NULL;
	}

	RSA_print_fp(stdout, rsa, 0);

	len = strlen(str);
	rsa_len = RSA_size(rsa);

	en = (char*)malloc(rsa_len + 1);
	memset(en, 0, rsa_len + 1);

	if (RSA_private_encrypt(rsa_len, (unsigned char*)str, (unsigned char*)en, rsa, RSA_NO_PADDING) < 0) {
		return NULL;
	}

	RSA_free(rsa);
	fclose(fp);

	return en;
}
//私钥解密
char* priKeyDecrypt(const char* str, const char* prikey_path)
{
    RSA* rsa = NULL;
    FILE* fp = NULL;
    char* de = NULL;
    int rsa_len = 0;

    if ((fp = fopen(prikey_path, "r")) == NULL) {
        return NULL;
    }

    if ((rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL) {
        return NULL;
    }

    RSA_print_fp(stdout, rsa, 0);

    rsa_len = RSA_size(rsa);
    de = (char*)malloc(rsa_len + 1);
    memset(de, 0, rsa_len + 1);

    if (RSA_private_decrypt(rsa_len, (unsigned char*)str, (unsigned char*)de, rsa, RSA_NO_PADDING) < 0) {
        return NULL;
    }

    RSA_free(rsa);
    fclose(fp);

    return de;
}
//公钥解密
char* pubKeyDecrypt(const char* str, const char* pubkey_path)
{
	RSA* rsa = NULL;
	FILE* fp = NULL;
	char* de = NULL;
	int rsa_len = 0;

	if ((fp = fopen(pubkey_path, "r")) == NULL) {
		return NULL;
	}

	if ((rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL)) == NULL) {
		return NULL;
	}

	RSA_print_fp(stdout, rsa, 0);

	rsa_len = RSA_size(rsa);
	de = (char*)malloc(rsa_len + 1);
	memset(de, 0, rsa_len + 1);

	if (RSA_public_decrypt(rsa_len, (unsigned char*)str, (unsigned char*)de, rsa, RSA_NO_PADDING) < 0) {
		return NULL;
	}

	RSA_free(rsa);
	fclose(fp);

	return de;
}
int main(int argc, char* argv[])
{
    const char* src = "hello, world!";
    char* en = NULL;
    char* de = NULL;

    printf("src is: %s\n", src);

    //en = pubKeyEncrypt(src, PUBKEY);
    en = priKeyEncrypt(src, PRIKEY);
    printf("enc is: %s\n", en);
    std::string str = en;

    //de = priKeyDecrypt(en, PRIKEY);
    de = pubKeyDecrypt(en, PUBKEY);
    printf("dec is: %s\n", de);

    if (en != NULL) {
        free(en);
    }

    if (de != NULL) {
        free(de);
    }

    return 0;
}