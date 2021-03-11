/*
 *
 * Copyright (C) 2017 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_OPTEE_KEYSTORE_TA_H
#define ANDROID_OPTEE_KEYSTORE_TA_H

#include <pta_system.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "operations.h"
#include "tables.h"
#include "parsel.h"
#include "master_crypto.h"
#include "paddings.h"
#include "parameters.h"
#include "generator.h"
#include "mbedtls_proxy.h"
#include "crypto_aes.h"
#include "crypto_rsa.h"
#include "crypto_ec.h"

/*
 * KeyMaster message size
 */
#define KM_RECV_BUF_SIZE 8192

/* Max size of attestation challenge */
#define MAX_ATTESTATION_CHALLENGE 128

/* Empty definitions */
#define EMPTY_CERT_CHAIN {.entries = NULL, .entry_count = 0}
#define EMPTY_BLOB {.data = NULL, .data_length = 0}
#define EMPTY_KEY_BLOB {.key_material = NULL, .key_material_size = 0}
#define EMPTY_PARAM_SET {.params = NULL, .length = 0}
#define EMPTY_CHARACTS {					\
			.hw_enforced = EMPTY_PARAM_SET,		\
			.sw_enforced = EMPTY_PARAM_SET}
#define EMPTY_OPERATION {					\
			.key = NULL,				\
			.nonce = EMPTY_BLOB,			\
			.op_handle = UNDEFINED,			\
			.purpose = UNDEFINED,			\
			.padding = UNDEFINED,			\
			.mode = UNDEFINED,			\
			.sf_item = NULL,			\
			.last_access = NULL,			\
			.operation = TEE_HANDLE_NULL,		\
			.digest_op = TEE_HANDLE_NULL,		\
			.prev_in_size = UNDEFINED,		\
			.min_sec = UNDEFINED,			\
			.mac_length = UNDEFINED,		\
			.a_data_length = 0,			\
			.a_data = NULL,				\
			.do_auth = false,			\
			.got_input = false,			\
			.buffering = false,			\
			.padded = false,			\
			.first = true,				\
			.last_block = EMPTY_BLOB}

uint64_t identifier_rsa[] = {1, 2, 840, 113549, 1, 1, 1};
/* RSAPrivateKey ::= SEQUENCE {
 *    version Version,
 *    modulus INTEGER, -- n
 *    publicExponent INTEGER, -- e
 *    privateExponent INTEGER, -- d
 *    prime1 INTEGER, -- p
 *    prime2 INTEGER, -- q
 *    exponent1 INTEGER, -- d mod (p-1)
 *    exponent2 INTEGER, -- d mod (q-1)
 *    coefficient INTEGER -- (inverse of q) mod p }
 */

uint64_t identifier_ec[] = {1, 2, 840, 10045, 2, 1};
/* ECPrivateKey ::= SEQUNCE {
 *    version Version,
 *    secretValue OCTET_STRING,
 *    publicValue CONSTRUCTED {
 *        XYValue BIT_STRING } }
 */

typedef struct tee_km_context {
	bool version_info_set;
	uint32_t os_version;
	uint32_t os_patchlevel;
} tee_km_context_t;

static uint32_t TA_possibe_size(const uint32_t type,
				const uint32_t key_size,
				const keymaster_blob_t input,
				const uint32_t tag_len);


static keymaster_error_t TA_addRngEntropy(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_generateKey(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_getKeyCharacteristics(
					TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_importKey(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_exportKey(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_attestKey(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_upgradeKey(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_deleteKey(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_deleteAllKeys(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_destroyAttestationIds(
					TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_begin(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_update(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_finish(TEE_Param params[TEE_NUM_PARAMS]);

static keymaster_error_t TA_abort(TEE_Param params[TEE_NUM_PARAMS]);

#endif  /* ANDROID_OPTEE_KEYSTORE_TA_H */
