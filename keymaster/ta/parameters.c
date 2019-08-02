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

#include "parameters.h"
#include "generator.h"
const size_t kMinGcmTagLength = 12 * 8;
const size_t kMaxGcmTagLength = 16 * 8;

void TA_free_params(keymaster_key_param_set_t *params)
{
	DMSG("%s %d", __func__, __LINE__);
	if (!params->params)
		return;
	for (size_t i = 0; i < params->length; i++) {
		if (keymaster_tag_get_type(params->params[i].tag) == KM_BIGNUM
				|| keymaster_tag_get_type(params->
				params[i].tag) == KM_BYTES) {
			TEE_Free(params->params[i].key_param.blob.data);
		}
	}
	TEE_Free(params->params);
}

void TA_free_cert_chain(keymaster_cert_chain_t *cert_chain)
{
	DMSG("%s %d", __func__, __LINE__);
	if (!cert_chain->entries) {
		return;
	}

	for (size_t i = 0; i < cert_chain->entry_count; i++) {
		if (cert_chain->entries[i].data)
			TEE_Free(cert_chain->entries[i].data);
	}
	TEE_Free(cert_chain->entries);
}

void TA_add_to_params(keymaster_key_param_set_t *params,
		      const uint32_t key_size,
		      const uint64_t rsa_public_exponent)
{
	bool was_added = false;
	uint32_t curve = TA_get_curve_nist(key_size);
	DMSG("%s %d", __func__, __LINE__);

	if (curve == UNDEFINED) {
		DMSG("Failed to get ECC curve nist, key_size = %u", key_size);
	}

	if (key_size != UNDEFINED) {
		for (size_t i = 0; i < params->length; i++) {
			if (params->params[i].tag == KM_TAG_KEY_SIZE) {
				was_added = true;
				params->params[i].key_param.integer = key_size;
				break;
			}
		}
		if (!was_added) {
			(params->params + params->length)->tag = KM_TAG_KEY_SIZE;
			(params->params + params->length)->
					key_param.integer = key_size;
			params->length++;
		}
	}

	if (rsa_public_exponent != UNDEFINED) {
		was_added = false;
		for (size_t i = 0; i < params->length; i++) {
			if (params->params[i].tag == KM_TAG_RSA_PUBLIC_EXPONENT) {
				was_added = true;
					params->params[i].key_param.integer = rsa_public_exponent;
				break;
			}
		}
		if (!was_added) {
			(params->params + params->length)->tag = KM_TAG_RSA_PUBLIC_EXPONENT;
			(params->params + params->length)->
					key_param.integer = rsa_public_exponent;
			params->length++;
		}
	}

	if (curve != UNDEFINED && key_size != UNDEFINED) {
		was_added = false;
		for (size_t i = 0; i < params->length; i++) {
			if (params->params[i].tag == KM_TAG_EC_CURVE) {
				was_added = true;
					params->params[i].key_param.enumerated =
							TA_size_to_ECcurve(key_size);
				break;
			}
		}
		if (!was_added) {
			(params->params + params->length)->tag = KM_TAG_EC_CURVE;
			(params->params + params->length)->
					key_param.enumerated =
							TA_size_to_ECcurve(key_size);
			params->length++;
		}
	}
}

uint32_t get_digest_size(const keymaster_digest_t *digest)
{
	DMSG("%s %d", __func__, __LINE__);
	switch (*digest) {
	case KM_DIGEST_MD5:
		return KM_DIGEST_MD5_SIZE;
	case KM_DIGEST_SHA1:
		return KM_DIGEST_SHA1_SIZE;
	case KM_DIGEST_SHA_2_224:
		return KM_DIGEST_SHA_2_224_SIZE;
	case KM_DIGEST_SHA_2_256:
		return KM_DIGEST_SHA_2_256_SIZE;
	case KM_DIGEST_SHA_2_384:
		return KM_DIGEST_SHA_2_384_SIZE;
	case KM_DIGEST_SHA_2_512:
		return KM_DIGEST_SHA_2_512_SIZE;
	default:
		return 0;
	}
}

void TA_push_param(keymaster_key_param_set_t *enforced,
			const keymaster_key_param_t *param)
{
	DMSG("%s %d", __func__, __LINE__);
	enforced->params[enforced->length] = *param;
	enforced->length++;
}

keymaster_error_t TA_parse_params(const keymaster_key_param_set_t params_t,
				keymaster_algorithm_t *key_algorithm,
				uint32_t *key_size,
				uint64_t *key_rsa_public_exponent,
				keymaster_digest_t *key_digest,
				const bool import)
{
	bool check_min_mac_length = false;
	uint32_t min_mac_length = UNDEFINED;
	uint32_t digest_count = 0;
	bool is_ec_curve = false;
	keymaster_ec_curve_t ec_curve = KM_EC_CURVE_UNKNOWN;
	*key_size = UNDEFINED; /*set default value*/

	DMSG("%s %d", __func__, __LINE__);
	for (size_t i = 0; i < params_t.length; i++) {
		switch ((params_t.params + i)->tag) {
		case KM_TAG_ALGORITHM:
			*key_algorithm = (keymaster_algorithm_t)
				(params_t.params + i)->key_param.integer;
			break;
		case KM_TAG_KEY_SIZE:
			*key_size = (params_t.params + i)->key_param.integer;
			break;
		case KM_TAG_RSA_PUBLIC_EXPONENT:
			*key_rsa_public_exponent =
				(params_t.params + i)->key_param.long_integer;
			break;
		case KM_TAG_BLOCK_MODE:
			if (!check_min_mac_length && KM_MODE_GCM ==
					(params_t.params + i)->
					key_param.enumerated) {
				check_min_mac_length = true;
			}
			break;
		case KM_TAG_MIN_MAC_LENGTH:
			min_mac_length = (params_t.params + i)->
						key_param.integer;
			break;
		case KM_TAG_DIGEST:
			digest_count++;
			if (*key_digest == UNDEFINED) {
				*key_digest = (keymaster_digest_t)
				(params_t.params + i)->key_param.
							enumerated;
			}
			break;
		case KM_TAG_EC_CURVE:
			is_ec_curve = true;
			ec_curve = (keymaster_ec_curve_t)
					(params_t.params + i)->
						key_param.enumerated;
			break;
		default:
			DMSG("Unused parameter with TAG = %x",
					(params_t.params + i)->tag);
		}
	}
	//Check:
	if (*key_algorithm == KM_ALGORITHM_RSA && (*key_size % 8 != 0 ||
						*key_size > MAX_KEY_RSA)
						&& !import) {
		EMSG("RSA key size must be multiple of 8 and less than %u",
								MAX_KEY_RSA);
		return KM_ERROR_UNSUPPORTED_KEY_SIZE;
	}
	if (*key_algorithm == KM_ALGORITHM_RSA &&
			*key_rsa_public_exponent == 3 && import) {
		EMSG("RSA import public exponent '3' doesn't match the key");
		return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
	}
	if (*key_algorithm == KM_ALGORITHM_RSA && *key_size != UNDEFINED
			&& *key_size > 1024 && import) {
		EMSG("RSA import key size %d must be less than 1024", *key_size);
		return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
	}
	if (*key_algorithm == KM_ALGORITHM_HMAC && (*key_size % 8 != 0 ||
						*key_size > MAX_KEY_HMAC ||
						*key_size < MIN_KEY_HMAC)
						&& !import) {
		EMSG("HMAC key size must be multiple of 8 and in range from %d to %d",
						MIN_KEY_HMAC, MAX_KEY_HMAC);
		return KM_ERROR_UNSUPPORTED_KEY_SIZE;
	}
	if (min_mac_length == UNDEFINED && ((*key_algorithm == KM_ALGORITHM_AES &&
					check_min_mac_length) ||
					*key_algorithm == KM_ALGORITHM_HMAC)) {
		EMSG("Min MAC length must be specified for AES GCM mode and HMAC");
		return KM_ERROR_MISSING_MIN_MAC_LENGTH;
	}
	if (*key_algorithm == KM_ALGORITHM_AES && check_min_mac_length &&
			(min_mac_length % 8 != 0 || min_mac_length < MIN_MML
			|| min_mac_length > MAX_MML)) {
		EMSG("Min MAC length must be multiple of 8 in range from 96 to 128");
		return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;
	}
	if (*key_algorithm == KM_ALGORITHM_HMAC && (min_mac_length % 8 != 0
			|| min_mac_length < MIN_MML_HMAC)) {
		EMSG("Min MAC length must be multiple and at least 64");
		return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;
	}
	if (*key_algorithm == KM_ALGORITHM_HMAC && digest_count != 1) {
		EMSG("For MAC algorithm only one digest must be specified");
		return KM_ERROR_UNSUPPORTED_DIGEST;
	}
	if (*key_algorithm == KM_ALGORITHM_EC) {
		/*EC key generation requests may have tag EC_CURVE, KEY_SIZE or both*/
		if (*key_size != UNDEFINED && is_ec_curve == true) {
			/*If the request contains both,
			 * use the curve specified by Tag::EC_CURVE,
			 * and validate that the specified key size is appropriate*/
			if (ec_curve != TA_size_to_ECcurve(*key_size)) {
				EMSG("For EC algorithm specified key size"
						"is not appropriate for that curve");
				return KM_ERROR_INVALID_ARGUMENT;
			} else {
				*key_size = TA_ECcurve_to_size(ec_curve);
			}
		} else if (*key_size == UNDEFINED && is_ec_curve == true) {
			/*If the request only contains Tag::EC_CURVE, use the specified*/
			*key_size = TA_ECcurve_to_size(ec_curve);
		}

		if ((*key_size == 224 || ec_curve == KM_EC_CURVE_P_224) && import) {
			EMSG("EC import key size must be greater than '224'");
			return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
		}
	}
	return KM_ERROR_OK;
}

keymaster_error_t TA_fill_characteristics(
			keymaster_key_characteristics_t *characteristics,
			const keymaster_key_param_set_t *params,
			uint32_t *size)
{
	DMSG("%s %d", __func__, __LINE__);
	/* Freed before characteristics is destoyed by caller */
	characteristics->hw_enforced.params = TEE_Malloc(
					MAX_ENFORCED_PARAMS_COUNT *
					sizeof(keymaster_key_param_t),
					TEE_MALLOC_FILL_ZERO);
	if (!characteristics->hw_enforced.params) {
		EMSG("Failed to allocate memory for hw_enforced.params");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	characteristics->hw_enforced.length = 0;
	/* Freed before characteristics is destoyed by caller */
	characteristics->sw_enforced.params = TEE_Malloc(
					MAX_ENFORCED_PARAMS_COUNT *
					sizeof(keymaster_key_param_t),
					TEE_MALLOC_FILL_ZERO);
	if (!characteristics->sw_enforced.params) {
		EMSG("Failed to allocate memory for sw_enforced.params");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	characteristics->sw_enforced.length = 0;
	*size = 2 * SIZE_LENGTH; /* room of hw and sw size values */

	for (size_t i = 0; i < params->length; i++) {
		*size += sizeof(params->params[i]);
		if (keymaster_tag_get_type(params->params[i].tag) == KM_BIGNUM
				|| keymaster_tag_get_type(params->
				params[i].tag) == KM_BYTES) {
			*size += SIZE_LENGTH;
			*size += params->params[i].key_param.blob.data_length;
		}

		switch (params->params[i].tag) {
		case KM_TAG_INVALID:
		case KM_TAG_BOOTLOADER_ONLY:
		case KM_TAG_NONCE:
		case KM_TAG_AUTH_TOKEN:
		case KM_TAG_MAC_LENGTH:
		case KM_TAG_ASSOCIATED_DATA:
		case KM_TAG_UNIQUE_ID:
			EMSG("Unexpected TAG %x", params->params[i].tag);
			return KM_ERROR_INVALID_KEY_BLOB;
		case KM_TAG_ROLLBACK_RESISTANT:
		case KM_TAG_APPLICATION_ID:
		case KM_TAG_APPLICATION_DATA:
		case KM_TAG_ALL_APPLICATIONS:
		case KM_TAG_ROOT_OF_TRUST:
		case KM_TAG_RESET_SINCE_ID_ROTATION:
		case KM_TAG_ALLOW_WHILE_ON_BODY:
		case KM_TAG_ATTESTATION_CHALLENGE:
			/* Ignore these. */
			DMSG("Ignore these TAG %x", params->params[i].tag);
			break;
		case KM_TAG_ORIGIN:
		case KM_TAG_PURPOSE:
		case KM_TAG_ALGORITHM:
		case KM_TAG_KEY_SIZE:
		case KM_TAG_RSA_PUBLIC_EXPONENT:
		case KM_TAG_BLOB_USAGE_REQUIREMENTS:
		case KM_TAG_PADDING:
		case KM_TAG_BLOCK_MODE:
		case KM_TAG_MIN_SECONDS_BETWEEN_OPS:
		case KM_TAG_MAX_USES_PER_BOOT:
		case KM_TAG_USER_SECURE_ID:
		case KM_TAG_NO_AUTH_REQUIRED:
		case KM_TAG_AUTH_TIMEOUT:
		case KM_TAG_CALLER_NONCE:
		case KM_TAG_MIN_MAC_LENGTH:
		case KM_TAG_KDF:
		case KM_TAG_EC_CURVE:
		case KM_TAG_ECIES_SINGLE_HASH_MODE:
		case KM_TAG_DIGEST:
		case KM_TAG_OS_VERSION:
		case KM_TAG_OS_PATCHLEVEL:
			TA_push_param(&characteristics->
				hw_enforced, params->params + i);
			break;
		case KM_TAG_USER_AUTH_TYPE:
			if ((hw_authenticator_type_t) params->params[i]
						.key_param.enumerated ==
						HW_AUTH_PASSWORD)
				TA_push_param(&characteristics->
					hw_enforced, params->params + i);
			else
				TA_push_param(&characteristics->
					sw_enforced, params->params + i);
			break;
		case KM_TAG_ACTIVE_DATETIME:
		case KM_TAG_ORIGINATION_EXPIRE_DATETIME:
		case KM_TAG_USAGE_EXPIRE_DATETIME:
		case KM_TAG_USER_ID:
		case KM_TAG_ALL_USERS:
		case KM_TAG_CREATION_DATETIME:
		case KM_TAG_INCLUDE_UNIQUE_ID:
		case KM_TAG_EXPORTABLE:
			TA_push_param(&characteristics->
				sw_enforced, params->params + i);
			break;
		default:
			DMSG("Unused parameter with TAG = %x",
					params->params[i].tag);
			break;
		}
	}
	return KM_ERROR_OK;
}

inline uint32_t TA_blob_size(const keymaster_blob_t *blob)
{
	DMSG("%s %d", __func__, __LINE__);
	return BLOB_SIZE_AKMS(blob);
}

uint32_t TA_characteristics_size(
			const keymaster_key_characteristics_t *characteristics)
{
	uint32_t size = 0;
	DMSG("%s %d", __func__, __LINE__);

	size += SIZE_LENGTH;
	for (size_t i = 0; i < characteristics->hw_enforced.length; i++) {
		size += SIZE_OF_ITEM(characteristics->hw_enforced.params);
		if (keymaster_tag_get_type(characteristics->
				hw_enforced.params[i].tag) == KM_BIGNUM ||
		    keymaster_tag_get_type(characteristics->
				hw_enforced.params[i].tag) == KM_BYTES) {
			size += TA_blob_size(&((characteristics->hw_enforced.params + i)->
					key_param.blob));
		}
	}

	size += SIZE_LENGTH;
	for (size_t i = 0; i < characteristics->sw_enforced.length; i++) {
		size += SIZE_OF_ITEM(characteristics->sw_enforced.params);
		if (keymaster_tag_get_type(characteristics->
				sw_enforced.params[i].tag) == KM_BIGNUM ||
		    keymaster_tag_get_type(characteristics->
				sw_enforced.params[i].tag) == KM_BYTES) {
			size += TA_blob_size(&((characteristics->sw_enforced.params + i)->
					key_param.blob));
		}
	}

	return size;
}

uint32_t TA_param_set_size(
		const keymaster_key_param_set_t *params)
{
	uint32_t size = 0;
	DMSG("%s %d", __func__, __LINE__);

	size += SIZE_LENGTH;
	for (size_t i = 0; i < params->length; i++) {
		size += SIZE_OF_ITEM(params->params);

		if (keymaster_tag_get_type(params->params[i].tag) == KM_BIGNUM
				|| keymaster_tag_get_type(params->
				params[i].tag) == KM_BYTES) {
			size += TA_blob_size(&(params->params[i].key_param.blob));
		}
	}

	return size;
}

uint32_t TA_cert_chain_size(
		const keymaster_cert_chain_t *cert_chain)
{
	uint32_t size = 0;
	DMSG("%s %d", __func__, __LINE__);

	size += SIZE_LENGTH;
	for (size_t i = 0; i < cert_chain->entry_count; i++) {
		size += SIZE_LENGTH;
		size += cert_chain->entries[i].data_length;
	}
	return size;
}

void TA_add_origin(keymaster_key_param_set_t *params_t,
		const keymaster_key_origin_t origin, const bool replace_origin)
{
	bool origin_added = false;
	DMSG("%s %d", __func__, __LINE__);

	for (size_t i = 0; i < params_t->length; i++) {
		if (params_t->params[i].tag == KM_TAG_ORIGIN) {
			origin_added = true;
			if (replace_origin) {
				params_t->params[i].key_param.enumerated
							= (uint32_t) origin;
			}
			break;
		}
	}
	if (!origin_added) {
		(params_t->params + params_t->length)->tag = KM_TAG_ORIGIN;
		(params_t->params + params_t->length)->
						key_param.enumerated = origin;
		params_t->length++;
	}
}

void TA_add_creation_datetime(keymaster_key_param_set_t *params_t, bool replace)
{
	bool datetime_added = false;
	TEE_Time time;
	TEE_GetSystemTime(&time);
	DMSG("%s %d", __func__, __LINE__);

	/*Replace if present*/
	for (size_t i = 0; i < params_t->length; i++) {
		if (params_t->params[i].tag == KM_TAG_CREATION_DATETIME) {
			datetime_added = true;
			if (replace) {
				params_t->params[i].key_param.date_time =
					(uint64_t)(time.seconds) * 1000 +
						   time.millis;
			}
			break;
		}
	}
	/*Add parameter*/
	if (!datetime_added) {
		(params_t->params + params_t->length)->tag = KM_TAG_CREATION_DATETIME;
		(params_t->params + params_t->length)->
						key_param.date_time
						= (uint64_t)(time.seconds) * 1000
								+ time.millis;
		params_t->length++;
	}
}

void TA_add_os_version_patchlevel(keymaster_key_param_set_t *params_t,
				  uint32_t os_version,
				  uint32_t os_patchlevel)
{
	size_t i;
	DMSG("%s %d", __func__, __LINE__);

	for (i = 0; i < params_t->length; i++) {
		if (params_t->params[i].tag == KM_TAG_OS_VERSION) {
			params_t->params[i].key_param.integer = os_version;
			break;
		}
	}
	if (i == params_t->length) {
		(params_t->params + params_t->length)->tag = KM_TAG_OS_VERSION;
		(params_t->params + params_t->length)->
						key_param.integer = os_version;
		params_t->length++;
	}

	for (i = 0; i < params_t->length; i++) {
		if (params_t->params[i].tag == KM_TAG_OS_PATCHLEVEL) {
			params_t->params[i].key_param.integer = os_patchlevel;
			break;
		}
	}
	if (i == params_t->length) {
		(params_t->params + params_t->length)->tag = KM_TAG_OS_PATCHLEVEL;
		(params_t->params + params_t->length)->
						key_param.integer = os_patchlevel;
		params_t->length++;
	}
}

void TA_add_ec_curve(keymaster_key_param_set_t *params_t, uint32_t key_size)
{
	bool tag_added = false;
	keymaster_ec_curve_t curve = TA_size_to_ECcurve(key_size);
	DMSG("%s %d", __func__, __LINE__);

	for (size_t i = 0; i < params_t->length; i++) {
		if (params_t->params[i].tag == KM_TAG_EC_CURVE)
			tag_added = true;
	}
	if (!tag_added) {
		(params_t->params + params_t->length)->tag = KM_TAG_EC_CURVE;
		(params_t->params + params_t->length)->
						key_param.integer =
							(uint32_t)curve;
		params_t->length++;
	}
}

bool cmpBlobParam(const keymaster_blob_t blob,
		const keymaster_key_param_t param)
{
	DMSG("%s %d", __func__, __LINE__);
	return blob.data_length != param.key_param.blob.data_length ||
		TEE_MemCompare(blob.data, param.key_param.blob.data,
		blob.data_length);
}

keymaster_error_t TA_check_params(const keymaster_key_param_set_t *key_params,
				const keymaster_key_param_set_t *in_params,
				keymaster_algorithm_t *algorithm,
				const keymaster_purpose_t op_purpose,
				keymaster_digest_t *op_digest,
				keymaster_block_mode_t *op_mode,
				keymaster_padding_t *op_padding,
				uint32_t *mac_length,
				keymaster_blob_t *nonce,
				uint32_t *min_sec, bool *do_auth,
				uint8_t *key_id)
{
	hw_auth_token_t auth_token;
	hw_authenticator_type_t auth_type = HW_AUTH_NONE;
	keymaster_blob_t client_id = {.data = NULL, .data_length = 0};
	keymaster_blob_t app_data = {.data = NULL, .data_length = 0};
	keymaster_digest_t digest[7];
	uint32_t digest_count = 0;
	keymaster_padding_t padding[6];
	uint32_t padding_count = 0;
	keymaster_block_mode_t block_mode[4];
	uint32_t block_mode_count = 0;
	keymaster_purpose_t purpose[4];
	uint32_t purpose_count = 0;
	uint64_t suid[MAX_SUID];
	uint32_t suid_count = 0;
	uint32_t max_uses = UNDEFINED;
	uint32_t auth_timeout = UNDEFINED;
	uint32_t min_mac_length = UNDEFINED;
	uint32_t key_size = UNDEFINED;
	bool soft_fail = false;
	bool supported_purpose = false;
	bool caller_nonce_fail = false;
	bool no_auth_req = false;
	bool match;
	bool caller_nonce = false;
	keymaster_error_t res = KM_ERROR_OK;

	DMSG("%s %d", __func__, __LINE__);
	for (size_t i = 0; i < key_params->length; i++) {
		switch (key_params->params[i].tag) {
		case KM_TAG_KEY_SIZE:
			DMSG("KM_TAG_KEY_SIZE");
			key_size = key_params->params[i].key_param.integer;
			break;
		case KM_TAG_ALGORITHM:
			DMSG("KM_TAG_ALGORITHM");
			*algorithm = (keymaster_algorithm_t)
				key_params->params[i].key_param.integer;
			break;
		case KM_TAG_APPLICATION_ID:
			DMSG("KM_TAG_APPLICATION_ID");
			client_id = key_params->params[i].key_param.blob;
			break;
		case KM_TAG_APPLICATION_DATA:
			DMSG("KM_TAG_APPLICATION_DATA");
			app_data = key_params->params[i].key_param.blob;
			break;
		case KM_TAG_PURPOSE:
			DMSG("KM_TAG_PURPOSE");
			purpose[purpose_count] = (keymaster_purpose_t)
				key_params->params[i].key_param.enumerated;
			purpose_count++;
			break;
		case KM_TAG_MIN_SECONDS_BETWEEN_OPS:
			DMSG("KM_TAG_MIN_SECONDS_BETWEEN_OPS");
			*min_sec = key_params->params[i].key_param.integer;
			break;
		case KM_TAG_MAX_USES_PER_BOOT:
			DMSG("KM_TAG_MAX_USES_PER_BOOT");
			max_uses = key_params->params[i].key_param.integer;
			break;
		case KM_TAG_USER_SECURE_ID:
			DMSG("KM_TAG_USER_SECURE_ID");
			if (suid_count + 1 > MAX_SUID) {
				EMSG("To many SUID. Expected max count %u",
								MAX_SUID);
				break;
			}
			suid[suid_count] =
				key_params->params[i].key_param.long_integer;
			suid_count++;
			break;
		case KM_TAG_CALLER_NONCE:
			DMSG("KM_TAG_CALLER_NONCE");
			caller_nonce =
				key_params->params[i].key_param.boolean;
			break;
		case KM_TAG_AUTH_TIMEOUT:
			DMSG("KM_TAG_AUTH_TIMEOUT");
			auth_timeout =
				key_params->params[i].key_param.integer;
			break;
		case KM_TAG_USER_AUTH_TYPE:
			DMSG("KM_TAG_USER_AUTH_TYPE");
			auth_type = (hw_authenticator_type_t)
				key_params->params[i].key_param.enumerated;
			break;
		case KM_TAG_BLOCK_MODE:
			DMSG("KM_TAG_BLOCK_MODE");
			block_mode[block_mode_count] =
				(keymaster_block_mode_t) key_params->
					params[i].key_param.integer;
			block_mode_count++;
			break;
		case KM_TAG_DIGEST:
			DMSG("KM_TAG_DIGEST");
			digest[digest_count] = (keymaster_digest_t)
				key_params->params[i].key_param.integer;
			digest_count++;
			break;
		case KM_TAG_PADDING:
			DMSG("KM_TAG_PADDING");
			padding[padding_count] = (keymaster_padding_t)
				key_params->params[i].key_param.integer;
			padding_count++;
			break;
		case KM_TAG_MIN_MAC_LENGTH:
			DMSG("KM_TAG_MIN_MAC_LENGTH");
			min_mac_length =
				key_params->params[i].key_param.integer;
			break;
		case KM_TAG_NO_AUTH_REQUIRED:
			DMSG("KM_TAG_NO_AUTH_REQUIRED");
			no_auth_req =
				key_params->params[i].key_param.boolean;
			break;
		case KM_TAG_MAC_LENGTH:
			DMSG("KM_TAG_MAC_LENGTH");
			*mac_length =
				in_params->params[i].key_param.integer;
			break;
		default:
			DMSG("Unused parameter with tag 0x%x",
					key_params->params[i].tag);
		}
	}

	for (uint32_t z = 0; z < purpose_count; z++) {
		DMSG("purpose[%u] = %d", z, purpose[z]);
	}
	DMSG("op_purpose = %d purpose_count = %u",
			op_purpose, purpose_count);

	if (*algorithm == KM_ALGORITHM_EC &&
				(op_purpose == KM_PURPOSE_ENCRYPT ||
				op_purpose == KM_PURPOSE_DECRYPT)) {
		EMSG("Decrypt/encrypt operation is not supported by EC algorithm");
		res = KM_ERROR_UNSUPPORTED_PURPOSE;
		goto out_cp;
	}
	if (*algorithm == KM_ALGORITHM_HMAC &&
				(op_purpose == KM_PURPOSE_ENCRYPT ||
				op_purpose == KM_PURPOSE_DECRYPT)) {
		EMSG("Decrypt/encrypt operation is not supported by HMAC algorithm");
		res = KM_ERROR_UNSUPPORTED_PURPOSE;
		goto out_cp;
	}
	soft_fail = (*algorithm == KM_ALGORITHM_RSA ||
		*algorithm == KM_ALGORITHM_EC) &&
		(op_purpose == KM_PURPOSE_ENCRYPT ||
		op_purpose == KM_PURPOSE_VERIFY);
	if (!soft_fail) {
		for (uint32_t z = 0; z < purpose_count; z++) {
			if (purpose[z] == op_purpose) {
				supported_purpose = true;
				break;
			}
		}
		if (!supported_purpose) {
			EMSG("Key does not support such purpose");
			res = KM_ERROR_INCOMPATIBLE_PURPOSE;
			goto out_cp;
		}
	}

	for (size_t j = 0; j < in_params->length; j++) {
		DMSG("in_params->params[%zu].tag = 0x%x",
				j, in_params->params[j].tag);
		switch (in_params->params[j].tag) {
		case KM_TAG_APPLICATION_ID:
			if (cmpBlobParam(client_id,
					in_params->params[j])) {
				EMSG("Wrong client_id");
				res = KM_ERROR_INVALID_KEY_BLOB;
				goto out_cp;
			}
			break;
		case KM_TAG_APPLICATION_DATA:
			if (cmpBlobParam(app_data,
					in_params->params[j])) {
				EMSG("Wrong app_data");
				res = KM_ERROR_INVALID_KEY_BLOB;
				goto out_cp;
			}
			break;
		case KM_TAG_CALLER_NONCE:
			caller_nonce_fail = !caller_nonce &&
				in_params->params[j].key_param.boolean;
			break;
		case KM_TAG_AUTH_TOKEN:
			TEE_MemMove(&auth_token,
				in_params->params[j].key_param.blob.data,
				in_params->params[j].
					key_param.blob.data_length);
			break;
		case KM_TAG_BLOCK_MODE:
			if (*op_mode != UNDEFINED) {
				EMSG("To many block mode tags");
				res = KM_ERROR_UNSUPPORTED_BLOCK_MODE;
				goto out_cp;
			}
			*op_mode = (keymaster_block_mode_t)
				in_params->params[j].key_param.enumerated;
			break;
		case KM_TAG_DIGEST:
			if (*op_digest != UNDEFINED) {
				EMSG("To many digest tags");
				res = KM_ERROR_UNSUPPORTED_DIGEST;
				goto out_cp;
			}
			*op_digest = (keymaster_digest_t)
				in_params->params[j].key_param.enumerated;
			break;
		case KM_TAG_PADDING:
			if (*op_padding != UNDEFINED) {
				EMSG("To many padding tags");
				res = KM_ERROR_UNSUPPORTED_PADDING_MODE;
				goto out_cp;
			}
			*op_padding = (keymaster_padding_t)
				in_params->params[j].key_param.enumerated;
			break;
		case KM_TAG_NONCE:
			caller_nonce_fail = !caller_nonce;
			*nonce = in_params->params[j].key_param.blob;
			break;
		case KM_TAG_MAC_LENGTH:
			if (*mac_length == UNDEFINED)
				*mac_length =
					in_params->params[j].key_param.integer;
			break;
		default:
			DMSG("Unused parameter with tag 0x%x",
					in_params->params[j].tag);
		}
	}
	if (*algorithm == KM_ALGORITHM_RSA) {
		if ((*op_padding == KM_PAD_RSA_PKCS1_1_5_SIGN ||
				*op_padding == KM_PAD_RSA_PSS) &&
				op_purpose != KM_PURPOSE_SIGN &&
				op_purpose != KM_PURPOSE_VERIFY) {
			EMSG("Padding modes KM_PAD_RSA_PKCS1_1_5_SIGN and KM_PAD_RSA_PSS "
			     "supports only SIGN and VERIFY purposes");
			return KM_ERROR_UNSUPPORTED_PADDING_MODE;
		} else if ((*op_padding == KM_PAD_RSA_PKCS1_1_5_ENCRYPT ||
				*op_padding == KM_PAD_RSA_OAEP) &&
				op_purpose != KM_PURPOSE_ENCRYPT &&
				op_purpose != KM_PURPOSE_DECRYPT) {
			EMSG("Padding modes KM_PAD_RSA_PKCS1_1_5_SIGN and KM_PAD_RSA_PSS "
			     "supports only SIGN and VERIFY purposes");
			return KM_ERROR_UNSUPPORTED_PADDING_MODE;
		}
		if (*op_padding == KM_PAD_RSA_PSS &&
				*op_digest == KM_DIGEST_NONE &&
				get_digest_size(op_digest) + 22 > key_size) {
			EMSG("RSA padding mode KM_PAD_RSA_PSS can not be used with "
			     "KM_DIGEST_NONE and key size must be at least 22 bytes "
			     "larger than digest output size");
			return KM_ERROR_INCOMPATIBLE_DIGEST;
		}
		if (*op_padding == KM_PAD_RSA_PSS &&
				(get_digest_size(op_digest) * 2 + 16) > key_size) {
			EMSG("RSA padding mode KM_PAD_RSA_PSS and key size must be larger than digest output size");
			return KM_ERROR_INCOMPATIBLE_DIGEST;
		}
		if (*op_padding == KM_PAD_RSA_OAEP &&
				*op_digest == KM_DIGEST_NONE) {
			EMSG("RSA padding mode KM_PAD_RSA_OAEP can not be used with "
			     "KM_DIGEST_NONE");
			return KM_ERROR_INCOMPATIBLE_DIGEST;
		}
		if (*op_padding == KM_PAD_PKCS7) {
			EMSG("RSA padding mode KM_PAD_PKCS7 can not be used");
			return KM_ERROR_UNSUPPORTED_PADDING_MODE;
		}
		if (*op_padding == UNDEFINED) {
			EMSG("RSA unsupported operation padding");
			return KM_ERROR_UNSUPPORTED_PADDING_MODE;
		}
	}
	if (soft_fail) {
		/* No need to do all other checks for public key operations */
		goto out_cp;
	}
	/* RSA, EC, HMAC    KM_PAD_RSA_PKCS1_1_5_ENCRYPT
	 * padding does not require a digest
	 */
	if (*algorithm != KM_ALGORITHM_AES &&
			*op_padding != KM_PAD_RSA_PKCS1_1_5_ENCRYPT) {
		match = false;
		if (*algorithm == KM_ALGORITHM_RSA &&
				*op_padding == KM_PAD_NONE) {
			if ((op_purpose == KM_PURPOSE_SIGN ||
					op_purpose == KM_PURPOSE_VERIFY) &&
					*op_digest != KM_DIGEST_NONE) {
				EMSG("RSA with padding KM_PAD_NONE and purpose SIGN or VIRIFY "
				     "must use KM_DIGEST_NONE");
				res = KM_ERROR_INCOMPATIBLE_DIGEST;
				goto out_cp;
			}
		}
		if (*op_digest == UNDEFINED &&
				*algorithm != KM_ALGORITHM_RSA &&
				*op_padding != KM_PAD_NONE &&
				op_purpose != KM_PURPOSE_ENCRYPT &&
				op_purpose != KM_PURPOSE_DECRYPT) {
			EMSG("Operation digest is not set");
			res = KM_ERROR_UNSUPPORTED_DIGEST;
			goto out_cp;
		}
		for (uint32_t i = 0; i < digest_count; i++) {
			if (*op_digest == digest[i]) {
				match = true;
				break;
			}
		}
		if (*op_digest != UNDEFINED && !match) {
			EMSG("Key does not support such digest");
			res = KM_ERROR_INCOMPATIBLE_DIGEST;
			goto out_cp;
		}
	}
	if (*algorithm == KM_ALGORITHM_HMAC || (*algorithm == KM_ALGORITHM_AES
				&& *op_mode == KM_MODE_GCM)) {
		/* HMAC, AES GCM */
		if (min_mac_length == UNDEFINED) {
			EMSG("Min MAC Length must be specified");
			res = KM_ERROR_MISSING_MIN_MAC_LENGTH;
			goto out_cp;
		}
		if (*mac_length == UNDEFINED) {
			if (*algorithm == KM_ALGORITHM_AES) {
				*mac_length = kMaxGcmTagLength;
			} else if (*algorithm == KM_ALGORITHM_HMAC) {
				*mac_length = min_mac_length;/*FIXME*/
			} else {
				EMSG("MAC Length must be specified");
				res = KM_ERROR_MISSING_MAC_LENGTH;
				goto out_cp;
			}
		}
		if (min_mac_length % 8 != 0) {
			EMSG("Min MAC Length must be a multiple of 8");
			res = KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;
			goto out_cp;
		}
		if (*mac_length % 8 != 0) {
			EMSG("MAC Length (%u) must be a multiple of 8",
								*mac_length);
			res = KM_ERROR_UNSUPPORTED_MAC_LENGTH;
			goto out_cp;
		}
		if (*algorithm == KM_ALGORITHM_AES &&
					(min_mac_length < kMinGcmTagLength ||
					min_mac_length > kMaxGcmTagLength)) {
			res = KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;
			goto out_cp;
		}
		if (*mac_length < min_mac_length) {
			EMSG("MAC length must be greater than Min MAC Length");
			res = KM_ERROR_INVALID_MAC_LENGTH;
			goto out_cp;
		}
		if (*algorithm == KM_ALGORITHM_HMAC) {
			if (*mac_length > get_digest_size(op_digest)) {
				EMSG("MAC Length is more than digest size");
				res = KM_ERROR_UNSUPPORTED_MAC_LENGTH;
			}
		} else {
			if (*mac_length > MAX_GCM_MAC) {
				EMSG("MAC Length of AES GCM must be less 128");
				res = KM_ERROR_UNSUPPORTED_MAC_LENGTH;
			}
		}
		if (res != KM_ERROR_OK)
			goto out_cp;
	}
	if (*algorithm != KM_ALGORITHM_HMAC&& *algorithm != KM_ALGORITHM_EC) {
		/* AES, RSA */
		match = false;
		if (*op_padding == UNDEFINED) {
			EMSG("Operation padding is not set");
			res = KM_ERROR_UNSUPPORTED_PURPOSE;
			goto out_cp;
		}
		for (uint32_t i = 0; i < padding_count; i++) {
			if (*op_padding == padding[i]) {
				match = true;
				break;
			}
		}
		if (!match) {
			EMSG("Key does not support such padding");
			res = KM_ERROR_INCOMPATIBLE_PADDING_MODE;
			goto out_cp;
		}
		if (*algorithm == KM_ALGORITHM_AES) {
			/* AES */
			match = false;
			if (*op_mode == UNDEFINED) {
				EMSG("Operation block mode is not set");
				res = KM_ERROR_UNSUPPORTED_BLOCK_MODE;
				goto out_cp;
			}
			for (uint32_t i = 0; i < block_mode_count; i++) {
				if (*op_mode == block_mode[i]) {
					match = true;
					break;
				}
			}
			if (!match) {
				EMSG("Key does not support such blobk mode");
				res = KM_ERROR_INCOMPATIBLE_BLOCK_MODE;
				goto out_cp;
			}
			if (((*op_mode == KM_MODE_GCM ||
					*op_mode == KM_MODE_CTR) &&
					*op_padding != KM_PAD_NONE) ||
					((*op_mode == KM_MODE_ECB ||
					*op_mode == KM_MODE_CBC) &&
					*op_padding != KM_PAD_NONE
					&& *op_padding != KM_PAD_PKCS7)) {
				EMSG("Mode does not compatible with padding");
				res = KM_ERROR_INCOMPATIBLE_PADDING_MODE;
				goto out_cp;
			}
			if (nonce->data_length > 0 && nonce->data_length != 12 &&
					nonce->data_length != 16) {
				EMSG("Wrong nonce length is prohibited %ld", nonce->data_length);
				res = KM_ERROR_INVALID_NONCE;
				goto out_cp;
			}
		}
	}
	if (is_origination_purpose(op_purpose) && (caller_nonce_fail
			|| (!caller_nonce && nonce->data_length > 0
			&& nonce->data != NULL))) {
		EMSG("Caller Nonce is prohibited for this key");
		res = KM_ERROR_CALLER_NONCE_PROHIBITED;
		goto out_cp;
	}
	if (!no_auth_req) {
		if (auth_timeout == UNDEFINED && suid_count > 0)
			*do_auth = true;
		if (suid_count > 0 && auth_timeout != UNDEFINED) {
			res = TA_check_auth_token(suid, suid_count,
						auth_type, &auth_token);
			if (res != KM_ERROR_OK)
				goto out_cp;
		} else {
			EMSG("Authentication failed. Key can not be used");
			res = KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
			goto out_cp;
		}
	}
	if (*min_sec != UNDEFINED) {
		res = TA_check_key_use_timer(key_id, *min_sec);
		if (res != KM_ERROR_OK)
			goto out_cp;
	}
	if (max_uses != UNDEFINED) {
		res = TA_count_key_uses(key_id, max_uses);
		if (res != KM_ERROR_OK)
			goto out_cp;
	}
out_cp:
	return res;
}

inline bool is_origination_purpose(const keymaster_purpose_t purpose)
{
	DMSG("%s %d", __func__, __LINE__);
	return purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_SIGN;
}

keymaster_error_t TA_check_permission(const keymaster_key_param_set_t *params,
				const keymaster_blob_t client_id,
				const keymaster_blob_t app_data,
				bool *exportable)
{
	bool client_id_checked = false;
	bool app_data_checked = false;
	bool client_id_same = false;
	bool app_data_same = false;

	DMSG("%s %d", __func__, __LINE__);
	for (size_t i = 0; i < params->length; i++) {
		DMSG("in_params->params[%zu].tag = %d",
				i, params->params[i].tag);
		if (client_id_checked && app_data_checked && *exportable)
			break;
		switch (params->params[i].tag) {
		case KM_TAG_APPLICATION_ID:
			client_id_checked = true;
			if (client_id.data_length != params->params[i].
						key_param.blob.data_length)
				break;
			client_id_same = TEE_MemCompare(client_id.data,
					params->params[i].key_param.blob.data,
					client_id.data_length);
			break;
		case KM_TAG_APPLICATION_DATA:
			app_data_checked = true;
			if (app_data.data_length !=
				params->params[i].key_param.blob.data_length)
				break;
			app_data_same = TEE_MemCompare(app_data.data,
					params->params[i].key_param.blob.data,
					app_data.data_length);
			break;
		case KM_TAG_EXPORTABLE:
			*exportable = params->params[i].key_param.boolean;
			break;
		default:
			break;
		}
	}
	if ((app_data_checked && app_data_same != 0) ||
		   (client_id_checked && client_id_same != 0)) {
		EMSG("Invalid client id or app data!");
		return KM_ERROR_INVALID_KEY_BLOB;
	}
	return KM_ERROR_OK;
}
