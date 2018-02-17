// pake.c
// 2017-02-17 Hannah Davis <davi2495@umn.edu>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "hila5_sha3.h"
#include "hila5_endian.h"
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
static void slow_vsub(int32_t d[HILA5_N],
    const int32_t a[HILA5_N], const int32_t b[HILA5_N])
{
    for (int i = 0; i < HILA5_N; i++)
        d[i] = (a[i]-b[i]+5*HILA5_Q) % HILA5_Q;
}
int crypto_pake_keypair(uint8_t *pk, uint8_t *sk, const char *pw){
    int32_t a[HILA5_N], e[HILA5_N], g[HILA5_N], t[HILA5_N];

    init_pow1945();                     // make sure initialized

    // Create secret key
    hila5_psi16(t);                     // (t is a temporary variable)
    slow_ntt(a, t, 27);                 // a = 3**3 * NTT(Psi_16)

    // Public key
    hila5_psi16(t);                     // t = Psi_16
    slow_ntt(e, t, 27);                 // e = 3**3 * NTT(Psi_16) -- noise
    randombytes(pk, HILA5_SEED_LEN);    // Random seed for g
    hila5_parse(t, pk);                 // (t =) g = parse(seed)

    slow_vmul(t, a, t);
    slow_vadd(t, t, e);                 // A = NTT(g * a + e)

    //hash password and add to A
    hila5_parse_xi(g, pw, strlen(pw));
    slow_vadd(t, t, g);
    hila5_pack14(pk + HILA5_SEED_LEN, t);   // pk = seed | A

    hila5_pack14(sk, a);                // pack secret key
    // SHA3 hash of password is stored with secret key
    hila5_pack14(sk + HILA5_PACKED14, g);

    return PAKE_SUCCESS;                           // SUCCESS
}

int crypto_pake_enc(uint8_t *ct, uint8_t *authkey, char *authS,
    const uint8_t *pk, const char *pw){
  int i;
  int32_t a[HILA5_N], b[HILA5_N], e[HILA5_N], g[HILA5_N], t[HILA5_N];
  uint64_t z[8];
  hila5_sha3_ctx_t sha3;

  init_pow1945();                     // make sure initialized

  hila5_unpack14(a, pk + HILA5_SEED_LEN); // decode m = public key
  hila5_parse_xi(b, pw, strlen(pw));         // compute gamma
  hila5_pack14(authkey, b);
  slow_vsub(a, a, b);                // decode A = m-gamma

  for (i = 0; i < HILA5_MAX_ITER; i++) {
      hila5_psi16(t);                 // recipients' ephemeral secret
      slow_ntt(b, t, 27);             // b = 3**3 NTT(Psi_16)
      slow_vmul(e, a, b);
      slow_intt(t, e);                // t = a * b  (approx. share "y")
      slow_smul(t, 1416);             // scale by 1416 = 1 / (3**6 * 1024)
      // Safe bits -- may fail (with about 1% probability);
      memset(z, 0, sizeof(z));        // ct = .. | sel | rec, z = payload
      if (hila5_safebits(ct + HILA5_PACKED14, //
          ct + HILA5_PACKED14 + HILA5_PACKED1, (uint8_t *) z, t) == 0){
          break;
      }
  }
  if (i == HILA5_MAX_ITER)            // FAIL: too many repeats
      return -1;
  HILA5_ENDIAN_FLIP64(z, 8);
  xe5_cod(&z[4], z);                  // create linear error correction code

  HILA5_ENDIAN_FLIP64(z, 8);
  memcpy(ct + HILA5_PACKED14 + HILA5_PACKED1 + HILA5_PAYLOAD_LEN,
      &z[4], HILA5_ECC_LEN);          // ct = .. | encrypted error cor. code
  memcpy(authkey+HILA5_PACKED14, z, HILA5_KEY_LEN);

  // Construct ciphertext
  hila5_parse(g, pk);                 // g = Parse(seed)
  hila5_psi16(t);                     // noise error
  slow_ntt(e, t, 27);                 // e = 3**3 * NTT(Psi_16)
  slow_vmul(t, g, b);                 // t = NTT(g * b)
  slow_vadd(t, t, e);                 // t = NTT(g * b + e)
  hila5_pack14(ct, t);                // public value in ct

  //compute authenticator
  hila5_sha3_init(&sha3, HILA5_KEY_LEN);
  hila5_sha3_update(&sha3, "ORACLE2",7);
  hila5_sha3_update(&sha3, pk+HILA5_SEED_LEN, HILA5_PACKED14);
  hila5_sha3_update(&sha3, ct, HILA5_PACKED14);
  hila5_sha3_update(&sha3, z, HILA5_KEY_LEN);     // actual shared secret z
  hila5_sha3_update(&sha3, authkey, HILA5_PACKED14);
  hila5_sha3_final(authS, &sha3);
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

  init_pow1945();                     // make sure initialized

  hila5_unpack14(a, sk);              // unpack secret key
  hila5_unpack14(b, ct);              // get B from ciphertext
  slow_vmul(a, a, b);                 // a * B
  slow_intt(b, a);                    // shared secret ("x") in b
  slow_smul(b, 1416);                 // scale by 1416 = (3^6 * 1024)^-1
  memset(z, 0x00, sizeof(z));
  if (hila5_select((uint8_t *) z,     // reconciliation
      ct + HILA5_PACKED14, ct + HILA5_PACKED14 + HILA5_PACKED1, b))
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

  //compute authenticator
  hila5_sha3_init(&sha3, HILA5_KEY_LEN);
  hila5_sha3_update(&sha3, "ORACLE2",7);
  hila5_sha3_update(&sha3, pk+HILA5_SEED_LEN, HILA5_PACKED14);
  hila5_sha3_update(&sha3, ct, HILA5_PACKED14);
  hila5_sha3_update(&sha3, z, HILA5_KEY_LEN);     // actual shared secret z
  hila5_sha3_update(&sha3, sk+HILA5_PACKED14, HILA5_PACKED14);
  hila5_sha3_final(check_auth, &sha3);
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
