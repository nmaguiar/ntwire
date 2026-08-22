#include <stddef.h>
#include <stdint.h>

int ntwire_bcrypt_pbkdf(const uint8_t *pass, size_t passlen, const uint8_t *salt,
                         size_t saltlen, uint8_t *key, size_t keylen, unsigned int rounds);
int ntwire_aes_ctr(const uint8_t *input, size_t inputlen, const uint8_t *key,
                   size_t keylen, const uint8_t *iv, uint8_t *output);
