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

// ������
enum EGMErrorCode
{
    GM_UTIL_CODE_OK = 0,
    GM_UTIL_CODE_CREATE_EV_KEY_FAILED, // ��Կ����ʧ��
    GM_UTIL_CODE_SM2_ENCRYPT_FAILED,   // SM2����ʧ��
    GM_UTIL_CODE_SM2_DECRYPT_FAILED,   // SM2����ʧ��
    GM_UTIL_CODE_NOT_SM2P256V1,        // ����Ĭ�ϵ�sm2p256v1��Բ���߲���
    GM_UTIL_CODE_INIT_BIO_FAILED,      // ��ʼ��BIOʧ��
    GM_UTIL_CODE_CIPHER_TEXT_TO_BIO_FAILED,      // �������ݴ洢��BIOʧ��
    GM_UTIL_CODE_BIO_DATA_TO_MEM_FAILED,      // BIO����ת�浽������ʧ��
    GM_UTIL_CODE_BIO_DATA_TO_CIPHER_TEXT_FAILED,      // BIO����ת��Ciphertext�ṹʧ��
};
extern "C"
{
    // ���ļ��ж��빫Կ/˽Կ���ݵ�string��,ʧ�ܷ��ؿ��ַ���
    UNIX_EXPORT string GmReadKeyFromFile(string strFileName);

    /**
     * @brief sm2���ܣ�ʹ��Ĭ�ϵ���Բ���߲���(NID_sm2p256v1)��ASN.1/DER���뷽ʽ(C1|C3|C2���뷽ʽ) ����ϣ���Ӵգ��㷨ʹ��sm3
     * @param strPubKey ��Կ����
     * @param strIn ��Ҫ���ܵ�����
     * @param strCiphertext ����,���ܺ�����Ĳ��ǿɼ��ַ�
     * @return ����GM_UTIL_ERR_OK��ʾ���ܳɹ�������ʧ�ܣ������EGMErrorCode����
     */
    UNIX_EXPORT int GmSm2Encrypt(string strPubKey, const string &strIn, string &strCiphertext);

    /**
     * @brief sm2���ܣ�ʹ��Ĭ�ϵ���Բ���߲���(NID_sm2p256v1)��ASN.1/DER���뷽ʽ(C1|C3|C2���뷽ʽ)����ϣ���Ӵգ��㷨ʹ��sm3
     * @param strPubKeyFile ˽Կ����
     * @param strCiphertext ��Ҫ���ܵ�����(���ǿɼ��ַ�)
     * @param strOut ���ܺ������
     * @return ����GM_UTIL_ERR_OK��ʾ���ܳɹ�������ʧ�ܣ������EGMErrorCode����
     */
    UNIX_EXPORT int GmSm2Decrypt(string strPriKey, const string &strCiphertext, string &strOut);

    // ������������ת����ʮ�������ַ���
    UNIX_EXPORT string GmByte2HexStr(const string &data, bool bLowerCase = true);

    // ��ʮ�������ַ���ת���ɶ�����
    UNIX_EXPORT string GmHexStr2Byte(const string& hex, bool bLowerCase = true);
}

// } // namespace GM
#endif // end __GM_UTIL_H__