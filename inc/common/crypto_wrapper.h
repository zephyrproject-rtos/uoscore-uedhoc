/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef CRYPTO_WRAPPER_H
#define CRYPTO_WRAPPER_H

#include "byte_array.h"
#include "oscore_edhoc_error.h"

#include "edhoc/suites.h"

/*Indicates what kind of operation a symmetric cipher will execute*/
enum aes_operation {
	ENCRYPT,
	DECRYPT,
};

/**
 * @brief			Calculates AEAD encryption decryption.
 * 
 * @param op 			Operation to be executed (ENCRYPT or DECRYPT).
 * @param[in] in		Input message.
 * @param[in] key 		The symmetric key to be used.
 * @param[in] nonce 		The nonce.
 * @param[in] aad 		Additional authenticated data.
 * @param[out] out 		The cipher text.
 * @param[in,out] tag 		The authentication tag.
 * @return 			Ok or error code.
 */
enum err aead(enum aes_operation op, const struct byte_array *in,
	      const struct byte_array *key, struct byte_array *nonce,
	      const struct byte_array *aad, struct byte_array *out,
	      struct byte_array *tag);

#ifdef MBEDTLS
#include <psa/crypto.h>

/**
 * @brief			AEAD using an already-resident PSA key.
 *
 * Identical to aead() except the key is identified by a PSA key id and is
 * neither imported nor destroyed here. This lets OSCORE use opaque/derived
 * keys whose bytes never enter the non-secure domain. MBEDTLS builds only.
 *
 * @param op			Operation to be executed (ENCRYPT or DECRYPT).
 * @param[in] in		Input message.
 * @param key_id		PSA key id of the AEAD key to use.
 * @param[in] nonce		The nonce.
 * @param[in] aad		Additional authenticated data.
 * @param[out] out		The cipher text / plaintext.
 * @param[in,out] tag		The authentication tag.
 * @return			Ok or error code.
 */
enum err aead_with_key_id(enum aes_operation op, const struct byte_array *in,
			  psa_key_id_t key_id, struct byte_array *nonce,
			  const struct byte_array *aad, struct byte_array *out,
			  struct byte_array *tag);

/**
 * @brief			Derives an OSCORE AEAD (Sender/Recipient) key.
 *
 * Runs HKDF-SHA-256 with the master secret as the secret input and returns the
 * result as a volatile PSA key handle. The key material is created directly
 * inside the PSA/secure domain and is never copied to the non-secure domain.
 * MBEDTLS builds only.
 *
 * @param master_secret_id	PSA derive key (PSA_KEY_TYPE_DERIVE) holding the
 *				OSCORE master secret (HKDF secret input).
 * @param[in] salt		OSCORE master salt (HKDF salt). May be empty.
 * @param[in] info		OSCORE HKDF info (CBOR-encoded).
 * @param bits			Derived key size in bits (128 for AES-CCM-16-64-128).
 * @param aead_alg		PSA AEAD algorithm the derived key may be used with.
 * @param[out] out_key_id	Receives the volatile derived-key handle.
 * @return			Ok or error code.
 */
enum err oscore_derive_aead_key(psa_key_id_t master_secret_id,
				const struct byte_array *salt,
				const struct byte_array *info, size_t bits,
				psa_algorithm_t aead_alg,
				psa_key_id_t *out_key_id);

/**
 * @brief			Derives the OSCORE Common IV into plain bytes.
 *
 * Same HKDF-SHA-256 derivation as oscore_derive_aead_key() but outputs raw
 * bytes; the Common IV is public so byte output is intentional. MBEDTLS only.
 *
 * @param master_secret_id	PSA derive key holding the OSCORE master secret.
 * @param[in] salt		OSCORE master salt (HKDF salt). May be empty.
 * @param[in] info		OSCORE HKDF info (CBOR-encoded).
 * @param[out] out		Receives the derived bytes; out->len produced.
 * @return			Ok or error code.
 */
enum err oscore_derive_iv_bytes(psa_key_id_t master_secret_id,
				const struct byte_array *salt,
				const struct byte_array *info,
				struct byte_array *out);
#endif /* MBEDTLS */

/**
 * @brief			Derives ECDH shared secret.
 * 
 * @param alg			The ECDH algorithm to be used.
 * @param[in] sk 		Private key.
 * @param[in] pk 		Public key.
 * @param[out] shared_secret 	The result.
 * @return 			Ok or error code.
 */
enum err shared_secret_derive(enum ecdh_alg alg, const struct byte_array *sk,
			      const struct byte_array *pk,
			      uint8_t *shared_secret);

/**
 * @brief			HKDF extract function, see rfc5869.
 * 
 * @param alg			Hash algorithm to be used.
 * @param[in] salt		Salt value.
 * @param[in] ikm 		Input keying material.
 * @param[out] out		The result.
 * @return 			Ok or error code.
 */
enum err hkdf_extract(enum hash_alg alg, const struct byte_array *salt,
		      struct byte_array *ikm, uint8_t *out);

/**
 * @brief			HKDF expand function, see rfc5869.
 * 
 * @param alg			Hash algorithm to be used.
 * @param[in] prk 		Input pseudo random key.
 * @param[in] info 		Info input parameter.
 * @param[out] out		The result.
 * @return 			Ok or error code.
 */
enum err hkdf_expand(enum hash_alg alg, const struct byte_array *prk,
		     const struct byte_array *info, struct byte_array *out);

/**
 * @brief			Computes a hash.
 * 
 * @param alg 			The hash algorithm to be used.
 * @param[in] in 		The input message.
 * @param[out] out 		The hash.
 * @return 			Ok or error code.
 */
enum err hash(enum hash_alg alg, const struct byte_array *in,
	      struct byte_array *out);

/**
 * @brief			Verifies an asymmetric signature.
 * @param alg			Signature algorithm to be used.
 * @param[in] sk 		Secret key.
 * @param[in] pk 		Public key.
 * @param[in] msg 		The message to be signed.
 * @param[out] out 		Signature.
 * @return 			Ok or error code.
 */
enum err sign(enum sign_alg alg, const struct byte_array *sk,
	      const struct byte_array *pk, const struct byte_array *msg,
	      uint8_t *out);

/**
 * @brief			Verifies an asymmetric signature.
 * 
 * @param alg 			Signature algorithm to be used.
 * @param[in] pk 		Public key.
 * @param[in] msg 		The signed message.
 * @param[in] sgn 		Signature.
 * @param[out] result 		True if the verification is successfully.
 * @return 			Ok or error code.
 */
enum err verify(enum sign_alg alg, const struct byte_array *pk,
		struct const_byte_array *msg, struct const_byte_array *sgn,
		bool *result);

/**
 * @brief			HKDF function used for the derivation of the 
 *				Common IV, Recipient/Sender keys.
 *
 * @param[in] master_secret	The master secret.
 * @param[in] master_salt 	The master salt.
 * @param[in] info 		A CBOR structure containing id, id_context, 
 * 				alg_aead, type, L. 
 * @param[out] out 		The derived Common IV, Recipient/Sender keys
 * @return 			Ok or error code.
 */
enum err hkdf_sha_256(struct byte_array *master_secret,
		      struct byte_array *master_salt, struct byte_array *info,
		      struct byte_array *out);

#ifdef EDHOC_MOCK_CRYPTO_WRAPPER
/*
 * Elliptic curve based signature algorithms generate signatures that are not 
 * deterministic. In order to test edhoc module against test vectors provided 
 * by the RFC authors, a mocking functionality has been added.
 *
 * When EDHOC_MOCK_CRYPTO_WRAPPER macro is defined, structure 
 * edhoc_crypto_mock_cb can be used to define values returned/generated by 
 * the sign() and aead() functions. Predefined value will be used only if the 
 * function has been called with arguments values matching those provided in
 * edhoc_crypto_mock_cb.aead_in_out / edhoc_crypto_mock_cb.sign_in_out structure.
 *
 * When there is no matching arguments, the function aead()/sign() will 
 * continue normally.
 */
struct edhoc_mock_aead_in_out {
	struct byte_array out;
	struct byte_array in;
	struct byte_array key;
	struct byte_array nonce;
	struct byte_array aad;
	struct byte_array tag;
};

struct edhoc_mock_sign_in_out {
	enum sign_alg curve;
	struct byte_array sk;
	struct byte_array pk;
	struct byte_array msg;
	struct byte_array out;
};

struct edhoc_mock_cb {
	int aead_in_out_count;
	struct edhoc_mock_aead_in_out *aead_in_out;
	int sign_in_out_count;
	struct edhoc_mock_sign_in_out *sign_in_out;
};

extern struct edhoc_mock_cb edhoc_crypto_mock_cb;
#endif // EDHOC_MOCK_CRYPTO_WRAPPER

#endif
