// api_p.h
// 2018-2-17 Hannah Davis <davi2495@umn.edu>

#ifndef _API_PPK_H_
#define _API_PPK_H_

// Definitions for HILA5 as a PAKE

#define CRYPTO_ALGNAME "HILA5_PPK"
#define CRYPTO_HASHBYTES 1792
#define CRYPTO_SECRETKEYBYTES 3*CRYPTO_HASHBYTES
#define CRYPTO_PUBLICKEYBYTES CRYPTO_HASHBYTES
#define CRYPTO_BYTES 32
#define CRYPTO_CIPHERTEXTBYTES 2012
// == Prototypes ===========================================================

// Generates a keypair - pk is the public key and sk is the secret key.
// pw is the password

int crypto_pake_keypair(unsigned char *pk, unsigned char *sk,
   const char *pw);

// Encrypt - pk is the public key, ct is a key encapsulation message
// (ciphertext), authkey is the secret information for authenticating ct,
// auth_S is the server's authenticator message, and pw is the password.
int crypto_pake_enc(unsigned char *ct, unsigned char *authkey, char *auth_S,
  const unsigned char *pk, const char *pw);

// Decrypt - ct is a key encapsulation message (ciphertext),
// sk is the private key, ss is the shared secret, pk is the public key, auth_C
// is the client's authenticator message, and auth_S is the server's
// authenticator message
int crypto_pake_dec(unsigned char *ss, char *auth_C, const char *auth_S,
  const unsigned char *ct, const unsigned char *pk, const unsigned char *sk);

// Final authentication - ss is the shared secret, auth_C is the client's
// authenticator message, pk is the public key, ct is the ciphertext, and
// authkey is the secret authentication information.
int crypto_pake_auth(unsigned char *ss, const char *auth_C,
  const unsigned char *pk, const unsigned char *ct, const unsigned char *authkey);

// Generates a keypair - pk is the public key and sk is the secret key. pw is
// the password
int crypto_ppk_keypair(unsigned char *pk, unsigned char *sk, const char *pw);

// Encrypt -- ct is the ciphertext, ss is the session key (which is gibberish
// unless the other party knows the password)
int crypto_ppk_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk,
   const char *pw);

// Decrypt -- ss is the session key, which will not match the servers' unless the
// password used to create the public key was correct
int crypto_ppk_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *pk,
                    const unsigned char *sk);
#endif
