#include <sys/types.h>
#include <string.h>
#include <stdio.h>

#if defined(_WIN32)
typedef unsigned char uint8_t;
typedef uint8_t u_int8_t;
typedef unsigned short uint16_t;
typedef uint16_t u_int16_t;
typedef unsigned uint32_t;
typedef uint32_t u_int32_t;
typedef unsigned long long uint64_t;
typedef uint64_t u_int64_t;
#define snprintf _snprintf
#define __attribute__(unused)
#else
#include <stdint.h>
#endif

#define explicit_bzero(s,n) memset(s, 0, n)
#define DEF_WEAK(f)

#define BCRYPT_VERSION '2'
#define BCRYPT_MAXSALT 16
#define BCRYPT_WORDS 6
#define BCRYPT_MINLOGROUNDS 4

#define BCRYPT_SALTSPACE (7 + (BCRYPT_MAXSALT * 4 + 2) / 3 + 1)
#define BCRYPT_HASHSPACE 61

int citadel_bcrypt_hashpass(const char *key, const char *salt, char *encrypted, size_t encryptedlen);
int citadel_encode_base64(char *, const u_int8_t *, size_t);
