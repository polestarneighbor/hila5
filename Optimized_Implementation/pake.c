// pake.c
// 2017-02-17 Hannah Davis <davi2495@umn.edu>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "hila5_sha3.h"
#include "hila5_endian.h"
#include "ms_priv.h"
#include "kem.h"

#define HILA5_PACKED_INT 1740
#define HILA5_EXPANSION_FACTOR 7894384086L
#define PAKE_CRYPTO_FAILURE -4
#define PAKE_AUTH_FAILURE -8
#define PAKE_INSUFFICIENT_BITS -16
#define PAKE_SUCCESS 0

static void hila5_parse_xi(int32_t v[HILA5_N],
                        const char *seed,
                        const int seed_len)
{
    hila5_sha3_ctx_t sha3;              // init SHA3 state for SHAKE-256
    uint8_t buf[2];                     // two byte output buffer
    uint32_t x;                          // random variable

    hila5_shake256_init(&sha3);         // initialize the context
    hila5_shake_update(&sha3, seed, seed_len);    // seed input
    hila5_shake_xof(&sha3);             // pad context to output mode

    // fill the vector with uniform samples
    for (int i = 0; i < HILA5_N; i++) {
        do {                            // rejection sampler
            hila5_shake_out(&sha3, buf, 2); // two bytes from SHAKE-256
            x = ((uint32_t) buf[0]) + (((uint32_t) buf[1]) << 8); // endianess
        } while (x >= 5 * HILA5_Q);     // reject
        v[i] = x;                       // reduction (mod q) unnecessary
    }
}
// Component-wise addition

void mslc_padd(const int32_t *a, const int32_t *b, int32_t *c, unsigned int n)
{
    unsigned int i;

    for (i = 0; i < n; i++) {
        c[i] = a[i] +b[i];
         mslc_two_reduce12289(c+i, n);
    }
}
// Component-wise addition

void mslc_psub(const int32_t *a, const int32_t *b, int32_t *c, unsigned int n)
{
    unsigned int i;

    for (i = 0; i < n; i++) {
        c[i] = a[i] - b[i];
        mslc_two_reduce12289(c+i, n);
    }
}

int crypto_pake_keypair(uint8_t *pk, uint8_t *sk, const char *pw){
    int32_t s[HILA5_N], e[HILA5_N], a[HILA5_N];


    // Secret key
    hila5_psi16(s);                         // s = NTT(Psi_16)
    mslc_ntt(a, mslc_psi_rev_ntt1024, HILA5_N);

    // Public key
    hila5_psi16(e);                         // e = NTT(Psi_16)
    mslc_ntt(e, mslc_psi_rev_ntt1024, HILA5_N);
    randombytes(pk, HILA5_SEED_LEN);        // Random seed for t
    hila5_parse(a, pk);                     // g = Parse(seed);
    mslc_pmuladd(a, s, e, a, HILA5_N);      // A = NTT(a * s + e)
    mslc_correction(a, HILA5_Q, HILA5_N);

    //hash password and add to A
    hila5_parse_xi(e, pw, strlen(pw));      // e now contains gamma
    mslc_padd(a, a, e, HILA5_N);            // m = A + gamma
    hila5_pack14(pk + HILA5_SEED_LEN, a);   // pk = seed | m

    hila5_pack14(sk, a);                // pack secret key
      // SHA3 hash of password is stored with secret key
    hila5_pack14(sk + HILA5_PACKED14, s);

    return PAKE_SUCCESS;                           // SUCCESS
}

int crypto_pake_enc(uint8_t *ct, uint8_t *authkey, char *authS,
    const uint8_t *pk, const char *pw){
  int i;
  int32_t a[HILA5_N], b[HILA5_N], e[HILA5_N], t[HILA5_N];
  uint64_t z[8];
  hila5_sha3_ctx_t sha3;

  hila5_unpack14(a, pk + HILA5_SEED_LEN); // decode m = public key
  hila5_parse_xi(b, pw, strlen(pw));         // compute gamma
  hila5_pack14(authkey, b);
  mslc_psub(a, a, b, HILA5_N);                // decode A = m-gamma
  for (i = 0; i < HILA5_MAX_ITER; i++) {
      hila5_psi16(t);                 // recipients' ephemeral secret
      mslc_ntt(t, mslc_psi_rev_ntt1024, HILA5_N);
      mslc_pmul(a, t, b, HILA5_N);        // b = a * t
      // 8281 = sqrt(-1) * 2^-10 * 3^-10, 7755 = 2^-10 * 3^-10
      mslc_intt(b, mslc_inv_rev_ntt1024, 8281, 7755, HILA5_N);
      mslc_two_reduce12289(b, HILA5_N);
      mslc_correction(b, HILA5_Q, HILA5_N);
      // Safe bits -- may fail (with about 1% probability);
      memset(z, 0, sizeof(z));        // ct = .. | sel | rec, z = payload
      printf("C says b is:");
      for (int j = 0; j < HILA5_N; j++){
        printf("%d ", b[j]);
      }
      printf("\n");
      if (hila5_safebits(ct + HILA5_PACKED14, //
          ct + HILA5_PACKED14 + HILA5_PACKED1, (uint8_t *) z, b) == 0){
          break;
      }
  }
  if (i == HILA5_MAX_ITER)            // FAIL: too many repeats
      return -1;
/*  printf("C says z is \n");
  for (int j = 0; j< HILA5_KEY_LEN/8; j++){
    printf("%lx ", z[j]);
  }
  printf("\n");*/
  HILA5_ENDIAN_FLIP64(z, 8);
  xe5_cod(&z[4], z);                  // create linear error correction code
  HILA5_ENDIAN_FLIP64(z, 8);

  memcpy(ct + HILA5_PACKED14 + HILA5_PACKED1 + HILA5_PAYLOAD_LEN,
      &z[4], HILA5_ECC_LEN);          // ct = .. | encrypted error cor. code
  memcpy(authkey+HILA5_PACKED14, z, HILA5_KEY_LEN);

  // Construct ciphertext
  hila5_parse(a, pk);                     // Construct ciphertext
  hila5_psi16(e);
  mslc_ntt(e, mslc_psi_rev_ntt1024, HILA5_N);
  mslc_pmuladd(a, t, e, a, HILA5_N);      // a = NTT(g * b + e)
  mslc_correction(a, HILA5_Q, HILA5_N);

  hila5_pack14(ct, a);                    // public value in ct

  //compute authenticator
  hila5_sha3_init(&sha3, HILA5_KEY_LEN);
  hila5_sha3_update(&sha3, "ORACLE2",7);
  hila5_sha3_update(&sha3, pk+HILA5_SEED_LEN, HILA5_PACKED14);
  hila5_sha3_update(&sha3, ct, HILA5_PACKED14);
  hila5_sha3_update(&sha3, z, HILA5_KEY_LEN);     // actual shared secret z
    hila5_sha3_final(authS, &sha3);
  hila5_sha3_update(&sha3, authkey, HILA5_PACKED14);


  // clear sensitive data
  hila5_sha3_init(&sha3, 0);
  memset(a, 0x00, sizeof(a));
  memset(b, 0x00, sizeof(b));
  memset(t, 0x00, sizeof(t));
  memset(e, 0x00, sizeof(e));
  memset(z, 0x00, sizeof(z));
  return PAKE_SUCCESS;
}

int crypto_pake_dec(uint8_t *ss, char *authC,
                    const char *authS,
                    const uint8_t *ct,
                    const uint8_t *pk,
                    const uint8_t *sk)
{
  int32_t a[HILA5_N], b[HILA5_N];
  uint64_t z[8];
  char check_auth[HILA5_KEY_LEN];
  hila5_sha3_ctx_t sha3;

  hila5_unpack14(a, sk);              // unpack secret key
  hila5_unpack14(b, ct);              // get B from ciphertext
  mslc_pmul(b, a, b, HILA5_N);
  // scaling factors
  // 3651 = sqrt(-1) * 2^-10 * 3^-12
  // 4958 = 2^-10 * 3^-12
  mslc_intt(b, mslc_inv_rev_ntt1024, 3651, 4958, HILA5_N);
  mslc_two_reduce12289(b, HILA5_N);
  mslc_correction(b, HILA5_Q, HILA5_N);
  printf("S says b is:");
  for (int j = 0; j < HILA5_N; j++){
    printf("%d ", b[j]);
  }
  printf("\n");
  memset(z, 0x00, sizeof(z));
  if (hila5_select((uint8_t *) z,     // reconciliation
      ct + HILA5_PACKED14,
      ct + HILA5_PACKED14 + HILA5_PACKED1, b))
      return PAKE_INSUFFICIENT_BITS;                      // FAIL: not enough bits
  // error correction -- decrypt with "one time pad" in payload
  for (int i = 0; i < HILA5_ECC_LEN; i++) {
      ((uint8_t *) &z[4])[i] ^=
          ct[HILA5_PACKED14 + HILA5_PACKED1 + HILA5_PAYLOAD_LEN + i];
  }
  HILA5_ENDIAN_FLIP64(z, 8);
  xe5_cod(&z[4], z);                  // linear code
  xe5_fix(z, &z[4]);                  // fix possible errors
  HILA5_ENDIAN_FLIP64(z, 8);
/*  printf("S says z is \n");
  for (int j = 0; j< HILA5_KEY_LEN/8; j++){
    printf("%lx ", z[j]);
  }
  printf("\n"); */
  //compute authenticator
  hila5_sha3_init(&sha3, HILA5_KEY_LEN);
  hila5_sha3_update(&sha3, "ORACLE2",7);
  hila5_sha3_update(&sha3, pk+HILA5_SEED_LEN, HILA5_PACKED14);
  hila5_sha3_update(&sha3, ct, HILA5_PACKED14);
  hila5_sha3_update(&sha3, z, HILA5_KEY_LEN);     // actual shared secret z
    hila5_sha3_final(check_auth, &sha3);
  hila5_sha3_update(&sha3, sk+HILA5_PACKED14, HILA5_PACKED14);

  if (strncmp(authS, check_auth,HILA5_KEY_LEN)!= 0){
    return PAKE_AUTH_FAILURE;
  }
  //compute session key
  hila5_sha3_init(&sha3, HILA5_KEY_LEN);          // final hash
  hila5_sha3_update(&sha3, "HILA5PAKEv10", 12);        // version ident
  hila5_sha3_update(&sha3, "ORACLE4", 7);
  hila5_sha3_update(&sha3, pk+HILA5_SEED_LEN, HILA5_PACKED14);
  hila5_sha3_update(&sha3, ct, HILA5_PACKED14);
  hila5_sha3_update(&sha3, z, HILA5_KEY_LEN);     // actual shared secret z
  hila5_sha3_update(&sha3, sk+HILA5_PACKED14, HILA5_PACKED14);
  hila5_sha3_final(ss, &sha3);                    // hash out to ss
  //compute authenticator
  hila5_sha3_init(&sha3, HILA5_KEY_LEN);
  hila5_sha3_update(&sha3, "ORACLE3",7);
  hila5_sha3_update(&sha3, pk+HILA5_SEED_LEN, HILA5_PACKED14);
  hila5_sha3_update(&sha3, ct, HILA5_PACKED14);
  hila5_sha3_update(&sha3, z, HILA5_KEY_LEN);     // actual shared secret z
  hila5_sha3_update(&sha3, sk+HILA5_PACKED14, HILA5_PACKED14);
  hila5_sha3_final(authC, &sha3);

  //clear sensitive data
  hila5_sha3_init(&sha3, 0);
  memset(b, 0x00, sizeof(b));
  memset(a, 0x00, sizeof(a));
  memset(z, 0x00, sizeof(z));
  return PAKE_SUCCESS;                         // SUCCESS
}

int crypto_pake_auth(uint8_t *ss, const char *auth_C,
    const uint8_t *pk, const uint8_t *ct, const uint8_t *authkey)
{
  char check_auth[HILA5_KEY_LEN];
  hila5_sha3_ctx_t sha3;
  //compute authenticator
  hila5_sha3_init(&sha3, HILA5_KEY_LEN);
  hila5_sha3_update(&sha3, "ORACLE3",7);
  hila5_sha3_update(&sha3, pk+HILA5_SEED_LEN, HILA5_PACKED14);
  hila5_sha3_update(&sha3, ct, HILA5_PACKED14);
  hila5_sha3_update(&sha3, authkey+HILA5_PACKED14, HILA5_KEY_LEN);     // actual shared secret z
  hila5_sha3_update(&sha3, authkey, HILA5_PACKED14);
  hila5_sha3_final(check_auth, &sha3);
  if (strncmp(auth_C, check_auth,HILA5_KEY_LEN)!= 0){
    return PAKE_AUTH_FAILURE;
  }
  //compute session key
  hila5_sha3_init(&sha3, HILA5_KEY_LEN);          // final hash
  hila5_sha3_update(&sha3, "HILA5PAKEv10", 12);        // version ident
  hila5_sha3_update(&sha3, "ORACLE4", 7);
  hila5_sha3_update(&sha3, pk+HILA5_SEED_LEN, HILA5_PACKED14);
  hila5_sha3_update(&sha3, ct, HILA5_PACKED14);
  hila5_sha3_update(&sha3, authkey+HILA5_PACKED14, HILA5_KEY_LEN);     // actual shared secret z
  hila5_sha3_update(&sha3, authkey, HILA5_PACKED14);
  hila5_sha3_final(ss, &sha3);
  return PAKE_SUCCESS;
}