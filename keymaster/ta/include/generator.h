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

#ifndef ANDROID_OPTEE_GENERATOR_H
#define ANDROID_OPTEE_GENERATOR_H

#define KM_ATTR_COUNT_AES_HMAC 1
#define KM_ATTR_COUNT_RSA 8
#define KM_ATTR_COUNT_EC 4
#define KM_AES_ATTR_SIZE 32
#define KM_HMAC_ATTR_SIZE 128
#define KM_RSA_ATTR_SIZE 512
#define KM_EC_ATTR_SIZE 256
#define KM_MAX_ATTR_SIZE 512
#define MAX_HMAC_MD5 512
#define MIN_HMAC_MD5 64
#define MAX_HMAC_SHA1 1024
#define MIN_HMAC_SHA1 64
#define MAX_HMAC_SHA224 1024
#define MIN_HMAC_SHA224 64
#define MAX_HMAC_SHA256 1024
#define MIN_HMAC_SHA256 64
#define MAX_HMAC_SHA384 1024
#define MIN_HMAC_SHA384 64
#define MAX_HMAC_SHA512 1024
#define MIN_HMAC_SHA512 64

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "master_crypto.h"
#include "parsel.h"
#include "parameters.h"

typedef struct tee_key_attributes
{
	TEE_Attribute *attrs;
	uint32_t attrs_count;
	uint32_t size;
	uint32_t type;
	keymaster_algorithm_t alg;
} tee_key_attributes;

/* Operations with keys */
keymaster_error_t TA_import_key(const keymaster_algorithm_t algorithm,
				const uint32_t key_size,
				uint8_t *key_material,
				const keymaster_digest_t digest,
				const TEE_Attribute *attrs_in,
				const uint32_t attrs_in_count);

keymaster_error_t TA_generate_key(const keymaster_algorithm_t algorithm,
				const uint32_t key_size,
				uint8_t *key_material,
				const keymaster_digest_t digest,
				const uint64_t rsa_public_exponent);

keymaster_error_t TA_restore_key(uint8_t *key_material,
				const keymaster_key_blob_t *key_blob,
				uint32_t *key_size, uint32_t *type,
				TEE_ObjectHandle *obj_h,
				keymaster_key_param_set_t *params_t);

/* Operations handling */
keymaster_error_t TA_create_operation(TEE_OperationHandle *operation,
				const TEE_ObjectHandle obj_h,
				const keymaster_purpose_t purpose,
				const keymaster_algorithm_t algorithm,
				const uint32_t key_size,
				const keymaster_blob_t nonce,
				const keymaster_digest_t digest,
				const keymaster_block_mode_t mode,
				const keymaster_padding_t padding,
				const uint32_t mac_length);

keymaster_error_t TA_create_digest_op(TEE_OperationHandle *digest_op,
				const keymaster_digest_t digest);

keymaster_error_t TA_check_hmac_key_size(keymaster_blob_t *key_data,
				uint32_t *key_size,
				const keymaster_digest_t digest);

keymaster_error_t TA_populate_key_attrs(uint8_t *key_material,
					tee_key_attributes *att);

keymaster_error_t TA_key_from_attrs(TEE_ObjectHandle *obj_h,
				    const tee_key_attributes *attrs);

keymaster_error_t TA_persistent_obj_from_attrs(TEE_ObjectHandle *obj_h,
					       TEE_Attribute *attrs,
					       uint32_t attrs_count,
					       const uint8_t* id,
					       uint32_t id_len);

keymaster_error_t TA_check_hmac_key(const uint32_t type, uint32_t *key_size);

TEE_Result TA_write_obj_attr(TEE_ObjectHandle attObj,
			     const uint8_t *buffer, const uint32_t buffSize);

bool is_attr_value(const uint32_t tag);

uint32_t purpose_to_mode(const keymaster_purpose_t purpose);

void free_attrs(TEE_Attribute *attrs, uint32_t size);

uint32_t TA_get_key_size(const keymaster_algorithm_t algorithm);

uint32_t *TA_get_attrs_list_short(const keymaster_algorithm_t algorithm,
						const bool short_list);

uint32_t *TA_get_attrs_list(const keymaster_algorithm_t algorithm);

uint32_t TA_get_curve_nist(const uint32_t key_size);

#endif/* ANDROID_OPTEE_GENERATOR_H */
