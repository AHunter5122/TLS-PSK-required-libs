#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>


// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES128 encryption in CBC-mode of operation and handles 0-padding.
// ECB enables the basic ECB 16-byte block algorithm. Both can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

static void test_encrypt_cbc(void);
//static void test_decrypt_cbc(void);

//#if defined(ECB) && ECB
class aes{
  public:
    aes();
    static void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t *output);
    static void AES128_ECB_decrypt(uint8_t* input, const uint8_t* key, uint8_t *output);

    //#endif // #if defined(ECB) && ECB


    //#if defined(CBC) && CBC

    static void AES128_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
    static void AES128_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
  private:
    static void XorWithIv(uint8_t* buf);
    static void BlockCopy(uint8_t* output, uint8_t* input);
    static void InvCipher(void);
    static void Cipher(void);
    static void InvShiftRows(void);
    static void InvSubBytes(void);
    static void InvMixColumns(void);
    static uint8_t Multiply(uint8_t x, uint8_t y);
    static void MixColumns(void);
    static uint8_t xtime(uint8_t x);
    static void ShiftRows(void);
    static void SubBytes(void);
    static void AddRoundKey(uint8_t round);
    static void KeyExpansion(void);
    static uint8_t getSBoxInvert(uint8_t num);
    static uint8_t getSBoxValue(uint8_t num);
    //static const uint8_t* Rcon;
    //static const uint8_t* rsbox;
    //static const uint8_t sbox;
    //static uint8_t* Iv;
    //static const uint8_t* Key;
    //static uint8_t* RoundKey;


//#endif // #if defined(CBC) && CBC
};


#endif //_AES_H_


