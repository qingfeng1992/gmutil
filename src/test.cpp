#include "gmutil.h"
#include <iostream>
#include <sstream>

int main(int argc, char** argv)
{
    string strPriKey = GmReadKeyFromFile("sm2_server_private_key.key");
    string strPubKey = GmReadKeyFromFile("sm2_server_public_key.key");
    string strText = "hello world, this is a test";
    string strCipher;
    string strOut;
    std::cout << "plaintext:" << strText << std::endl;
    int nRet = GmSm2Encrypt(strPubKey, strText, strCipher);
    if (GM_UTIL_CODE_OK != nRet)
    {
        cout << "GmSm2Encrypt fail" << endl;
    }
    string strCipherTextHex = GmByte2HexStr(strCipher);
    cout << "hex ciper text:" << strCipherTextHex << endl;
    //strCipherTextHex = "307c02201ceaad3e9ba4ee877c687e2631a7701fed30ddcde63202aa9add382643b97815022100d3f40f0c4fb9e115ea92c9c04515866ad91bba167ccff17b44d205fb688dc47c0420823cafe619f5d6e67934c4e5fc2a16ef611c12fc2d36f6b98c4a7f4f9b5a057904136d9670582cf637d4aefc4c6a25181a4a00e31e";
    string strCipher1 = GmHexStr2Byte(strCipherTextHex);
    if (strCipher1 == strCipher)
    {
        cout << "conver hex str to byte sucess" << endl;
    }
    nRet = GmSm2Decrypt(strPriKey, strCipher1, strOut);
    std::cout << "after decrypt:" << strOut << std::endl;

    return 0;
}