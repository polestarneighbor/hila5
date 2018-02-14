#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "hila5_sha3.h"
#include "hila5_endian.h"
#include "rng.h"
#include "api.h"

#define HILA5_PACKED_INT 1740
#define HILA5_EXPANSION_FACTOR 7894384086L
#define PAKE_CRYPTO_FAILURE -4
#define OVERFLOW -8
#define PAKE_SUCCESS 0

int pake_hashRq(int32_t d[HILA5_N],
    const unsigned char *pw, const int pw_len) {
/* writes a 1792-bit hash  of message to digest as a vector of R_q*/
  mpz_t bound;
  mpz_init_set_ui(bound, HILA5_Q);
  mpz_pow_ui(bound,bound,HILA_N);
  mpz_mul_ui(bound,bound, HILA5_EXPANSION_FACTOR);
  unsigned char digest[HILA5_PACKED_INT+1];
  digest[HILA5_PACKED_INT] = 0;
  mpz_t rq_digest;
  mpz_init(rq_digest);
  hila5_sha3(pw, pw_len, digest, HILA5_PACKED_INT);
  mpz_set_str(rq_digest, digest, 2);
  /*Shave remainders off rq_digest */
  for (int i = 0; i < HILA5_N; i++){
    d[i] = mpz_mod_ui(rq_digest, HILA5_Q, rq_digest);
  }
  return 0;
}

int crypto_pake_keypair(uint8_t *pk, uint8_t *sk, uint8_t *hash,
      const unsigned char *pw, const int pw_len){
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
    pake_hashRq(g, pw, pw_len);
    slow_ntt(g, g, 27);
    slow_vadd(t, t, g);
    hila5_pack14(pk + HILA5_SEED_LEN, t);   // pk = seed | A

    hila5_pack14(sk, a);                // pack secret key
    hila5_pack14(hash, g);
    // SHA3 hash of public key is stored with secret key due to API limitation
    hila5_sha3(pk, HILA5_PUBKEY_LEN, sk + HILA5_PACKED14, 32);

    return 0;                           // SUCCESS
}

int crypto_pake_enc(uint8_t *ct, uint8_t *ss, uint8_t *pw_hash, char *k,
    const uint8_t *pk, const unsigned char *pw, const int pw_len){
  int i;
  int32_t a[HILA5_N], b[HILA5_N], e[HILA5_N], g[HILA5_N], t[HILA5_N];
  uint64_t z[8];
  uint8_t hash[32];
  hila5_sha3_ctx_t sha3;

  init_pow1945();                     // make sure initialized

  hila5_unpack14(a, pk + HILA5_SEED_LEN); // decode m = public key
  pake_hashRq(b, pw, pw_len);         // compute gamma
  hila5_pack14(pw_hash, b);
  slow_ntt(b, b, 27);
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
          ct + HILA5_PACKED14 + HILA5_PACKED1, (uint8_t *) z, t) == 0)
          break;
  }
  if (i == HILA5_MAX_ITER)            // FAIL: too many repeats
      return -1;

  HILA5_ENDIAN_FLIP64(z, 8);
  xe5_cod(&z[4], z);                  // create linear error correction code
  HILA5_ENDIAN_FLIP64(z, 8);

  memcpy(ct + HILA5_PACKED14 + HILA5_PACKED1 + HILA5_PAYLOAD_LEN,
      &z[4], HILA5_ECC_LEN);          // ct = .. | encrypted error cor. code

  // Construct ciphertext
  hila5_parse(g, pk);                 // g = Parse(seed)
  hila5_psi16(t);                     // noise error
  slow_ntt(e, t, 27);                 // e = 3**3 * NTT(Psi_16)
  slow_vmul(t, g, b);                 // t = NTT(g * b)
  slow_vadd(t, t, e);                 // t = NTT(g * b + e)
  hila5_pack14(ct, t);                // public value in ct

  hila5_sha3_init(&sha3, HILA5_KEY_LEN);          // final hash
  hila5_sha3_update(&sha3, "HILA5PAKEv10", 8);        // version ident
  hila5_sha3(pk, HILA5_PUBKEY_LEN, hash, 32);     // SHA3(pk)
  hila5_sha3_update(&sha3, hash, 32);
  hila5_sha3(ct, HILA5_CIPHERTEXT_LEN, hash, 32); // SHA3(ct)
  hila5_sha3_update(&sha3, hash, 32);
  hila5_sha3_update(&sha3, z, HILA5_KEY_LEN);     // actual shared secret z
  hila5_sha3_final(ss, &sha3);                    // hash out to ss

  return 0;
}

int crypto_pake_dec( uint8_t *ss, char * k2,
                    const char * k,
                    const uint8_t *ct,
                    const uint8_t *sk,
                    const uint8_t *hash)
{
  int32_t a[HILA5_N], b[HILA5_N];
  uint64_t z[8];
  char * check_k[HILA5HILA5_KEY_LEN];
  uint8_t ct_hash[32];
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
      return -1;                      // FAIL: not enough bits

  // error correction -- decrypt with "one time pad" in payload
  for (int i = 0; i < HILA5_ECC_LEN; i++) {
      ((uint8_t *) &z[4])[i] ^=
          ct[HILA5_PACKED14 + HILA5_PACKED1 + HILA5_PAYLOAD_LEN + i];
  }
  HILA5_ENDIAN_FLIP64(z, 8);
  xe5_cod(&z[4], z);                  // linear code
  xe5_fix(z, &z[4]);                  // fix possible errors
  HILA5_ENDIAN_FLIP64(z, 8);

  hila5_sha3_init(&sha3, HILA5_KEY_LEN);              // final hash
  hila5_sha3_update(&sha3, "HILA5v10", 8);            // version identifier
  hila5_sha3_update(&sha3, sk + HILA5_PACKED14, 32);  // SHA3(pk)
  hila5_sha3(ct, HILA5_CIPHERTEXT_LEN, ct_hash, 32);  // hash the ciphertext
  hila5_sha3_update(&sha3, ct_hash, 32);              // SHA3(ct)
  hila5_sha3_update(&sha3, z, HILA5_KEY_LEN);         // shared secret
  hila5_sha3_final(ss, &sha3);

  return 0;                           // SUCCESS

}
