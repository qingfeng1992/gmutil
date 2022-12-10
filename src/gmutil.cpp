#include "gmutil.h"
#include <iostream>
#include<fstream>
#include<sstream>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sm2.h>
#include <openssl/bio.h>
//using namespace GM;

/**
 * @brief 使用公钥/私钥数据获取EV_KEY对象
 * @param key 公钥/私钥数据
 * @param is_public 是否公钥
 * @return 失败返回NULL
 */
static EC_KEY *CreateEC(unsigned char *key, int is_public)
{
    EC_KEY *ec_key = NULL;
    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(key, -1);
 
    if (keybio == NULL) {
        printf("%s", "[BIO_new_mem_buf]->key len=%d,Failed to Get Key", strlen((char *) key));
        return NULL;
    }
 
    if (is_public) {
        ec_key = PEM_read_bio_EC_PUBKEY(keybio, NULL, NULL, NULL);
    } else {
        ec_key = PEM_read_bio_ECPrivateKey(keybio, NULL, NULL, NULL);
    }
 
    if (ec_key == NULL) {
        printf("Failed to Get Key");
        BIO_free_all(keybio);
        return NULL;
    }

    BIO_free_all(keybio); // 此处是不是要free?
    return ec_key;
}

int GmSm2Encrypt(string strPubKey, const string &strIn, string &strCiphertext)
{
    EC_KEY *evKey = CreateEC((unsigned char *)strPubKey.c_str(), 1);
    if (NULL == evKey)
    {
        return GM_UTIL_CODE_CREATE_EV_KEY_FAILED;
    }
    
    // 目前只支持默认的sm2p256v1椭圆曲线参数
    if (!EC_KEY_is_sm2p256v1(evKey))
    {
        EC_KEY_free(evKey);
        return GM_UTIL_CODE_NOT_SM2P256V1;
    }

    // 加密后的密文会比明文长97字节
    unsigned char *buff = NULL;
    size_t outLen = 0;
    SM2CiphertextValue *cval = NULL;
    size_t mlen, clen;
    unsigned char *p;

    if (NULL == (cval = SM2_do_encrypt(EVP_sm3(), (const unsigned char *)strIn.c_str(), strIn.size(), evKey)))
    {
        EC_KEY_free(evKey);
        return GM_UTIL_CODE_SM2_ENCRYPT_FAILED;
    }
    
    BIO *bOut = BIO_new(BIO_s_mem());
    if (NULL == bOut)
    {
        EC_KEY_free(evKey);
        SM2CiphertextValue_free(cval);
        return GM_UTIL_CODE_INIT_BIO_FAILED;
    }

    if (i2d_SM2CiphertextValue_bio(bOut, cval) <= 0)
    {
        SM2CiphertextValue_free(cval);
        BIO_free(bOut);
        EC_KEY_free(evKey);
        return GM_UTIL_CODE_CIPHER_TEXT_TO_BIO_FAILED;
    }

    if (0 == (outLen = BIO_get_mem_data(bOut, (char **)&buff)))
    {
        SM2CiphertextValue_free(cval);
        BIO_free(bOut);
        EC_KEY_free(evKey);
        return GM_UTIL_CODE_BIO_DATA_TO_MEM_FAILED;
    }

    strCiphertext.assign((char *)buff, outLen);
    // 释放内存
    SM2CiphertextValue_free(cval);
    BIO_free(bOut);
    EC_KEY_free(evKey);
    // OPENSSL_free(buff); //此处释放会挂掉，不应该free，应该是在BIO_free的时候内存已经被释放掉
    return GM_UTIL_CODE_OK;
}


int GmSm2Decrypt(string strPriKey, const string &strCiphertext, string &strOut)
{
    EC_KEY *evKey = CreateEC((unsigned char *)strPriKey.c_str(), 0);
    if (NULL == evKey)
    {
        return GM_UTIL_CODE_CREATE_EV_KEY_FAILED;
    }

    if (!EC_KEY_is_sm2p256v1(evKey))
    {
        EC_KEY_free(evKey);
        return GM_UTIL_CODE_NOT_SM2P256V1;
    }
    BIO *bIn = NULL;
    bIn = BIO_new_mem_buf(strCiphertext.c_str(), strCiphertext.size());
    if (bIn == NULL)
    {
        EC_KEY_free(evKey);
        return GM_UTIL_CODE_INIT_BIO_FAILED;
    }

    int ret = 0;
	SM2CiphertextValue *cval = NULL;
	void *buf = NULL;
	size_t siz;
    const EVP_MD* md = EVP_sm3();

    if (NULL == (cval = d2i_SM2CiphertextValue_bio(bIn, NULL)))
    {
        BIO_free(bIn);
        EC_KEY_free(evKey);
        return GM_UTIL_CODE_BIO_DATA_TO_CIPHER_TEXT_FAILED;
    }

	if (0 == SM2_do_decrypt(md, cval, NULL, &siz, evKey) || !(buf = OPENSSL_malloc(siz)))
    {
        BIO_free(bIn);
        SM2CiphertextValue_free(cval);
        EC_KEY_free(evKey);
		return GM_UTIL_CODE_SM2_DECRYPT_FAILED;
	}

    if (0 == SM2_do_decrypt(md, cval, (unsigned char*)buf, &siz, evKey))
    {
        BIO_free(bIn);
        SM2CiphertextValue_free(cval);
        OPENSSL_free(buf);
        EC_KEY_free(evKey);
        return GM_UTIL_CODE_SM2_DECRYPT_FAILED;
    }
    
    strOut.assign((char*)buf, siz);
    // 释放内存
    BIO_free(bIn);
    SM2CiphertextValue_free(cval);
	OPENSSL_free(buf);
    EC_KEY_free(evKey);
    return GM_UTIL_CODE_OK;
}

static streamsize Read(istream &stream, char *buffer, streamsize count)
{
    streamsize reads = stream.rdbuf()->sgetn(buffer, count);
    stream.rdstate();
    stream.peek();
    return reads;
}

string GmReadKeyFromFile(string strFileName)
{
    fstream myfile;
	myfile.open(strFileName, ifstream::in | ifstream::binary);
	if (!myfile.is_open())
    {
        return "";
    }

    char buff[1024];
    std::ostringstream oss;
    int len;
    while (!myfile.eof())
    {
        size_t read = Read(myfile, buff, sizeof(buff));
        oss << string(buff, read);
    }

    myfile.close();
    return oss.str();
}

static char sDigit1[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
static char sDigit2[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
string GmByte2HexStr(const string& data, bool bLowerCase)
{
    char *sDigit = sDigit1;
    if (!bLowerCase)
    {
        sDigit = sDigit2;
    }
    const char* pData = data.c_str();
    char cTemp;
    string strHex;
    for (unsigned int i = 0; i < data.size(); i++)
    {
        cTemp = *pData;
        pData++;
        strHex += sDigit[(cTemp >> 4) & 0x0F];
        strHex += sDigit[cTemp & 0x0F];
    }

    return strHex;
}

string GmHexStr2Byte(const string& hex, bool bLowerCase)
{
    if (hex.size() % 2 != 0)
    {
        // 十六进制字符串必须是偶数长度
        return "";
    }

    char chA = 'a';
    if (!bLowerCase)
    {
        chA = 'A';
    }

    std::ostringstream oss;
    for (int i = 0; i < hex.size(); i += 2)
    {
        unsigned int highBit;
        if (hex[i] >= '0' && hex[i] <= '9')
        {
            highBit = hex[i] - '0';
        }
        else
        {
            highBit = hex[i] - chA + 10;
        }
        unsigned int lowBit;
        if (hex[i + 1] >= '0' && hex[i + 1] <= '9')
        {
            lowBit = hex[i + 1] - '0';
        }
        else
        {
            lowBit = hex[i + 1] - chA + 10;
        }
        unsigned char ch = (highBit << 4) + lowBit; 
        oss << ch;
    }

    return oss.str();
}