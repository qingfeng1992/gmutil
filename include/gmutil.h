#ifndef __GM_UTIL_H__
#define __GM_UTIL_H__
#include <string>
using namespace std;

#ifdef _WIN32
#define UNIX_EXPORT
#else
#define UNIX_EXPORT __attribute__((visibility("default")))
#endif
// namespace GM
//{

// 错误码
enum EGMErrorCode
{
    GM_UTIL_CODE_OK = 0,
    GM_UTIL_CODE_CREATE_EV_KEY_FAILED, // 密钥解析失败
    GM_UTIL_CODE_SM2_ENCRYPT_FAILED,   // SM2加密失败
    GM_UTIL_CODE_SM2_DECRYPT_FAILED,   // SM2解密失败
    GM_UTIL_CODE_NOT_SM2P256V1,        // 不是默认的sm2p256v1椭圆曲线参数
    GM_UTIL_CODE_INIT_BIO_FAILED,      // 初始化BIO失败
    GM_UTIL_CODE_CIPHER_TEXT_TO_BIO_FAILED,      // 加密数据存储到BIO失败
    GM_UTIL_CODE_BIO_DATA_TO_MEM_FAILED,      // BIO数据转存到缓冲区失败
    GM_UTIL_CODE_BIO_DATA_TO_CIPHER_TEXT_FAILED,      // BIO数据转成Ciphertext结构失败
};
extern "C"
{
    // 从文件中读入公钥/私钥数据到string中,失败返回空字符串
    UNIX_EXPORT string GmReadKeyFromFile(string strFileName);

    /**
     * @brief sm2加密，使用默认的椭圆曲线参数(NID_sm2p256v1)，ASN.1/DER编码方式(C1|C3|C2编码方式) ，哈希（杂凑）算法使用sm3
     * @param strPubKey 公钥数据
     * @param strIn 需要加密的数据
     * @param strCiphertext 密文,加密后的密文不是可见字符
     * @return 返回GM_UTIL_ERR_OK表示加密成功，否则失败，具体见EGMErrorCode定义
     */
    UNIX_EXPORT int GmSm2Encrypt(string strPubKey, const string &strIn, string &strCiphertext);

    /**
     * @brief sm2解密，使用默认的椭圆曲线参数(NID_sm2p256v1)，ASN.1/DER编码方式(C1|C3|C2编码方式)，哈希（杂凑）算法使用sm3
     * @param strPubKeyFile 私钥数据
     * @param strCiphertext 需要解密的数据(不是可见字符)
     * @param strOut 解密后的明文
     * @return 返回GM_UTIL_ERR_OK表示解密成功，否则失败，具体见EGMErrorCode定义
     */
    UNIX_EXPORT int GmSm2Decrypt(string strPriKey, const string &strCiphertext, string &strOut);

    // 将二进制数据转换成十六进制字符串
    UNIX_EXPORT string GmByte2HexStr(const string &data, bool bLowerCase = true);

    // 将十六进制字符串转换成二进制
    UNIX_EXPORT string GmHexStr2Byte(const string& hex, bool bLowerCase = true);
}

// } // namespace GM
#endif // end __GM_UTIL_H__