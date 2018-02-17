#ifndef _KEM_H_
#define _KEM_H_

#define HILA5_N                 1024
#define HILA5_Q                 12289
#define HILA5_B                 799
#define HILA5_MAX_ITER          100
#define HILA5_SEED_LEN          32
#define HILA5_KEY_LEN           32
#define HILA5_ECC_LEN           30
#define HILA5_PACKED1           (HILA5_N / 8)
#define HILA5_PACKED14          (14 * HILA5_N / 8)
#define HILA5_PAYLOAD_LEN       (HILA5_KEY_LEN + HILA5_ECC_LEN)
#define HILA5_PUBKEY_LEN        (HILA5_SEED_LEN + HILA5_PACKED14)
#define HILA5_PRIVKEY_LEN       (HILA5_PACKED14 + 32)
#define HILA5_CIPHERTEXT_LEN    (HILA5_PACKED14 + HILA5_PACKED1 + \
                                HILA5_PAYLOAD_LEN + HILA5_ECC_LEN)

// Prototype here so that we wouldn't have to find rng.h
int randombytes(unsigned char *x, unsigned long long xlen);

// Functionality from kem.c that we are stealing
void init_pow1945();
void hila5_psi16(int32_t v[HILA5_N]);
void slow_ntt(int32_t d[HILA5_N], const int32_t v[HILA5_N], int32_t c);
void hila5_parse(int32_t v[HILA5_N],
    const uint8_t *seed);
void slow_vmul(int32_t d[HILA5_N],
    const int32_t a[HILA5_N], const int32_t b[HILA5_N]);
void slow_vadd(int32_t d[HILA5_N],
    const int32_t a[HILA5_N], const int32_t b[HILA5_N]);
void slow_smul(int32_t v[HILA5_N], int32_t c);
void slow_intt(int32_t d[HILA5_N], const int32_t v[HILA5_N]);
void hila5_pack14(uint8_t d[HILA5_PACKED14], const int32_t v[HILA5_N]);
void hila5_unpack14(int32_t v[HILA5_N],
    const uint8_t d[HILA5_PACKED14]);
void xe5_cod(uint64_t r[4], const uint64_t d[4]);
int hila5_safebits(uint8_t sel[HILA5_PACKED1],
    uint8_t rec[HILA5_PAYLOAD_LEN],
    uint8_t pld[HILA5_PAYLOAD_LEN],
    const int32_t v[HILA5_N]);
void xe5_fix(uint64_t d[4], const uint64_t r[4]);
int hila5_select(uint8_t pld[HILA5_PAYLOAD_LEN],
    const uint8_t sel[HILA5_PACKED1],
    const uint8_t rec[HILA5_PAYLOAD_LEN],
    const int32_t v[HILA5_N]);
#endif
