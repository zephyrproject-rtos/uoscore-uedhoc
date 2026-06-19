/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef OSCORE_COSE_H
#define OSCORE_COSE_H

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

#ifdef OSCORE_PSA_OPAQUE_KEYS
#include <psa/crypto.h>
/* With opaque keys the Sender/Recipient keys are PSA handles, so the key is
   passed by id and the AEAD runs without exposing key bytes to NS. */
typedef psa_key_id_t oscore_key_t;
#else
typedef struct byte_array *oscore_key_t;
#endif

/**
 * @brief Decrypt the ciphertext
 * @param in_ciphertext: input ciphertext to be decrypted
 * @param out_plaintext: output plaintext
 * @param nonce the nonce
 * @param aad the aad
 * @param recipient_key the recipient key (PSA key id on MBEDTLS builds)
 * @return err
 */
enum err oscore_cose_decrypt(struct byte_array *in_ciphertext,
			     struct byte_array *out_plaintext,
			     struct byte_array *nonce, struct byte_array *aad,
			     oscore_key_t recipient_key);

/**
 * @brief Encrypt the plaintext
 * @param in_plaintext: input plaintext to be encrypted
 * @param out_ciphertext: output ciphertext with authentication tag (8 bytes)
 * @param nonce the nonce
 * @param sender_aad the aad
 * @param key the sender key (PSA key id on MBEDTLS builds)
 * @return err
 */
enum err oscore_cose_encrypt(struct byte_array *in_plaintext,
			     struct byte_array *out_ciphertext,
			     struct byte_array *nonce,
			     struct byte_array *sender_aad,
			     oscore_key_t key);
#endif
