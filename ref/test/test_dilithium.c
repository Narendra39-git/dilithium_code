#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>  // Include time.h for measuring execution time
#include "../randombytes.h"
#include "../sign.h"

#define MLEN 59
#define CTXLEN 14
#define NTESTS 10000

int main(void)
{
  size_t i, j;
  int ret;
  size_t mlen, smlen;
  uint8_t b;
  uint8_t ctx[CTXLEN] = {0};
  uint8_t m[MLEN + CRYPTO_BYTES];
  uint8_t m2[MLEN + CRYPTO_BYTES];
  uint8_t sm[MLEN + CRYPTO_BYTES];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  snprintf((char*)ctx, CTXLEN, "test_dilithium");

  // Start measuring time
  clock_t start_time, end_time;
  double keygen_time = 0.0, sign_time = 0.0, verify_time = 0.0;

  for(i = 0; i < NTESTS; ++i) {
    randombytes(m, MLEN);

    // Measure key generation time
    start_time = clock();
    crypto_sign_keypair(pk, sk);
    end_time = clock();
    keygen_time += ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    // Measure signing time
    start_time = clock();
    crypto_sign(sm, &smlen, m, MLEN, ctx, CTXLEN, sk);
    end_time = clock();
    sign_time += ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    // Measure verification time
    start_time = clock();
    ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk);
    end_time = clock();
    verify_time += ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    if(ret) {
      fprintf(stderr, "Verification failed\n");
      return -1;
    }
    if(smlen != MLEN + CRYPTO_BYTES) {
      fprintf(stderr, "Signed message lengths wrong\n");
      return -1;
    }
    if(mlen != MLEN) {
      fprintf(stderr, "Message lengths wrong\n");
      return -1;
    }
    for(j = 0; j < MLEN; ++j) {
      if(m2[j] != m[j]) {
        fprintf(stderr, "Messages don't match\n");
        return -1;
      }
    }

    randombytes((uint8_t *)&j, sizeof(j));
    do {
      randombytes(&b, 1);
    } while(!b);
    sm[j % (MLEN + CRYPTO_BYTES)] += b;
    ret = crypto_sign_open(m2, &mlen, sm, smlen, ctx, CTXLEN, pk);
    if(!ret) {
      fprintf(stderr, "Trivial forgeries possible\n");
      return -1;
    }
  }

  printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_BYTES = %d\n", CRYPTO_BYTES);
  
  // Print average execution time
  printf("Average Key Generation Time: %.6f seconds\n", keygen_time / NTESTS);
  printf("Average Signing Time: %.6f seconds\n", sign_time / NTESTS);
  printf("Average Verification Time: %.6f seconds\n", verify_time / NTESTS);

  return 0;
}
