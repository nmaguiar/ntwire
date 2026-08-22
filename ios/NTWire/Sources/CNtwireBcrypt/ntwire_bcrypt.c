#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include "bcrypt-kdf.h"
#include "ntwire_bcrypt.h"

static void ntwire_sha512(unsigned char *out, const unsigned char *input, unsigned long long inputlen) {
    CC_SHA512(input, (CC_LONG)inputlen, out);
}

int ntwire_bcrypt_pbkdf(const uint8_t *pass, size_t passlen, const uint8_t *salt,
                         size_t saltlen, uint8_t *key, size_t keylen, unsigned int rounds) {
    citadel_set_crypto_hash_sha512(ntwire_sha512);
    return citadel_bcrypt_pbkdf(pass, passlen, salt, saltlen, key, keylen, rounds);
}

int ntwire_aes_ctr(const uint8_t *input, size_t inputlen, const uint8_t *key,
                   size_t keylen, const uint8_t *iv, uint8_t *output) {
    CCCryptorRef cryptor = NULL;
    if (CCCryptorCreateWithMode(kCCDecrypt, kCCModeCTR, kCCAlgorithmAES, ccNoPadding,
                                iv, key, keylen, NULL, 0, 0, 0, &cryptor) != kCCSuccess) return -1;
    size_t moved = 0;
    CCCryptorStatus status = CCCryptorUpdate(cryptor, input, inputlen, output, inputlen, &moved);
    CCCryptorRelease(cryptor);
    return status == kCCSuccess && moved == inputlen ? 0 : -1;
}
