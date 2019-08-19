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
#include <stdio.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "common.h"
#include "ta_ca_defs.h"
#include "keystore_ta.h"
#include "attestation.h"

static TEE_TASessionHandle sessionSTA = TEE_HANDLE_NULL;
static TEE_TASessionHandle session_rngSTA = TEE_HANDLE_NULL;

static tee_km_context_t optee_km_context;

static void TA_init_km_context(void)
{
	memset(&optee_km_context, 0, sizeof(tee_km_context_t));
	optee_km_context.version_info_set = false;
}

TEE_Result TA_CreateEntryPoint(void)
{
	TEE_Result	res = TEE_SUCCESS;
	TEE_Param	params[TEE_NUM_PARAMS];

	const TEE_UUID asn1_parser_uuid = ASN1_PARSER_UUID;
	const TEE_UUID rng_entropy_uuid = PTA_SYSTEM_UUID /*RNG_ENTROPY_UUID*/;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	DMSG("%s %d", __func__, __LINE__);
	TA_init_km_context();
	TA_reset_operations_table();

	res = TA_create_secret_key();
	if (res != TEE_SUCCESS) {
		EMSG("Something wrong with secret key (%x)", res);
		goto exit;
	}

	res = TA_InitializeAuthTokenKey();
	if (res != TEE_SUCCESS) {
		EMSG("Something wrong with authorization token (%x)", res);
		goto exit;
	}

	res = TEE_OpenTASession(&asn1_parser_uuid, TEE_TIMEOUT_INFINITE,
			exp_param_types, params, &sessionSTA, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to create session with ASN.1 static TA (%x)", res);
		goto exit;
	}

	res = TEE_OpenTASession(&rng_entropy_uuid, TEE_TIMEOUT_INFINITE,
			exp_param_types, params, &session_rngSTA, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to create session with RNG static TA (%x)", res);
		goto exit;
	}

exit:
	return res;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("%s %d", __func__, __LINE__);
	TA_free_master_key();
	TEE_CloseTASession(sessionSTA);
	TEE_CloseTASession(session_rngSTA);
	sessionSTA = TEE_HANDLE_NULL;
	session_rngSTA = TEE_HANDLE_NULL;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS] __unused, void **sess_ctx __unused)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	DMSG("%s %d", __func__, __LINE__);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx __unused)
{
	DMSG("%s %d", __func__, __LINE__);
}

static uint32_t TA_possibe_size(const uint32_t type, const uint32_t key_size,
				const keymaster_blob_t input,
				const uint32_t tag_len)
{
	DMSG("%s %d", __func__, __LINE__);
	switch (type) {
	case TEE_TYPE_AES:
		/*
		 * Input can be extended to block size and one block
		 * can be added as a padding.
		 * Additionaly GCM tag can be added
		 */
		return ((input.data_length + BLOCK_SIZE - 1)
				/ BLOCK_SIZE + 1) * BLOCK_SIZE + tag_len;
	case TEE_TYPE_RSA_KEYPAIR:
		return (key_size + 7) / 8;
	case TEE_TYPE_ECDSA_KEYPAIR:
		/*
		 * Output is a sign with r and s parameters each sized as
		 * a key in ASN.1 format
		 */
		return 3 * key_size;
	default:/* HMAC */
		return KM_MAX_DIGEST_SIZE;
	}
}

static uint32_t tee_get_os_version(void)
{
	return optee_km_context.os_version;
}

static uint32_t tee_get_os_patchlevel(void)
{
	return optee_km_context.os_patchlevel;
}


static keymaster_error_t TA_configure(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	size_t  in_size = 0;
	uint8_t *out = NULL;
	keymaster_error_t res = KM_ERROR_OK;

	in = (uint8_t *) params[0].memref.buffer;
	in_size = (size_t) params[0].memref.size;
	in_end = in + in_size;
	out = (uint8_t *) params[1].memref.buffer;

	DMSG("%s %d", __func__, __LINE__);

	if (IS_OUT_OF_BOUNDS(in, in_end, sizeof(optee_km_context.os_version) +
								sizeof(optee_km_context.os_patchlevel))) {
		EMSG("Out of input array bounds on deserialization");
		return KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
	}
	/* parse parameters */
    if (!optee_km_context.version_info_set) {
        // Note that version info is now set by Configure, rather than by the
        // bootloader.  This is to ensure that system-only updates can be done,
        // to avoid breaking Project Treble.
        memcpy(&optee_km_context.os_version, in, sizeof(optee_km_context.os_version));
		in += 4;
        memcpy(&optee_km_context.os_patchlevel, in, sizeof(optee_km_context.os_patchlevel));
		in += 4;
        optee_km_context.version_info_set = true;
    }

	out += TA_serialize_rsp_err(out, &res);
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	return res;
}

//Adds caller-provided entropy to the pool
static keymaster_error_t TA_addRngEntropy(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	size_t  in_size = 0;
	uint8_t *out = NULL;
	uint8_t *data = NULL;		/* IN */
	uint32_t data_length = 0;		/* IN */
	uint32_t sta_param_types = TEE_PARAM_TYPES(
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param params_tee[TEE_NUM_PARAMS];
	keymaster_error_t res = KM_ERROR_OK;

	in = (uint8_t *) params[0].memref.buffer;
	in_size = (size_t) params[0].memref.size;
	in_end = in + in_size;
	out = (uint8_t *) params[1].memref.buffer;

	DMSG("%s %d", __func__, __LINE__);
	if (in_size == 0)
		return KM_ERROR_OK;
	if (IS_OUT_OF_BOUNDS(in, in_end, sizeof(data_length))) {
		EMSG("Out of input array bounds on deserialization");
		return KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
	}
	TEE_MemMove(&data_length, in, sizeof(data_length));
	in += sizeof(data_length);
	if (IS_OUT_OF_BOUNDS(in, in_end, data_length)) {
		EMSG("Out of input array bounds on deserialization");
		return KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
	}
	data = TEE_Malloc(data_length, TEE_MALLOC_FILL_ZERO);
	if (!data) {
		EMSG("Failed to allocate memory for data");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	TEE_MemMove(data, in, data_length);
	if (session_rngSTA == TEE_HANDLE_NULL) {
		EMSG("Session with RNG static TA is not opened");
		res = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
		goto out;
	}
	params_tee[0].memref.buffer = data;
	params_tee[0].memref.size = data_length;
	res = TEE_InvokeTACommand(session_rngSTA, TEE_TIMEOUT_INFINITE,
			PTA_SYSTEM_ADD_RNG_ENTROPY /*CMD_ADD_RNG_ENTROPY*/,
			sta_param_types, params_tee, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Invoke command for RNG static TA failed, res=%x", res);
		goto out;
	}
out:
	out += TA_serialize_rsp_err(out, &res);
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;
	if (data)
		TEE_Free(data);

	DHEXDUMP(params[1].memref.buffer, params[1].memref.size);
	return res;
}

//Generate new key and specify associated authorizations (key params)
static keymaster_error_t TA_generateKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *key_material = NULL;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;		/* IN */
	keymaster_key_blob_t key_blob = EMPTY_KEY_BLOB;		/* OUT */
	keymaster_key_characteristics_t characts = EMPTY_CHARACTS;/* OUT */
	keymaster_algorithm_t key_algorithm = UNDEFINED;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_digest_t key_digest = UNDEFINED;
	uint32_t key_buffer_size = 0; //For serialization of generated key
	uint32_t characts_size = 0;
	uint32_t key_size = UNDEFINED;
	uint64_t key_rsa_public_exponent = UNDEFINED;
	uint32_t os_version = 0xFFFFFFFF;
	uint32_t os_patchlevel = 0xFFFFFFFF;

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	DMSG("%s %d", __func__, __LINE__);
	in += TA_deserialize_auth_set(in, in_end, &params_t, false, &res);
	if (res != KM_ERROR_OK)
		goto exit;

	/* need add os version and patchlevel to key_description,
	* attest_key will check thess sections.
	* optee add these values in hal and pass to ta.
	*/
	os_version = tee_get_os_version();
	os_patchlevel = tee_get_os_patchlevel();

	/*Add additional parameters*/
	TA_add_origin(&params_t, KM_ORIGIN_GENERATED, true);
	TA_add_creation_datetime(&params_t, true);
	TA_add_os_version_patchlevel(&params_t, os_version, os_patchlevel);

	//Parse mandatory and optional parameters
	res = TA_parse_params(params_t, &key_algorithm, &key_size,
			      &key_rsa_public_exponent, &key_digest, false);
	if (res != KM_ERROR_OK)
		goto exit;

	if (key_size == UNDEFINED) {
		EMSG("Key size must be specified");
		res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
		goto exit;
	}
	if (key_algorithm == KM_ALGORITHM_RSA &&
			key_rsa_public_exponent == UNDEFINED) {
		EMSG("RSA public exponent is missed");
		res = KM_ERROR_INVALID_ARGUMENT;
		goto exit;
	}
	if (key_algorithm == KM_ALGORITHM_EC) {
		DMSG("key_algorithm == KM_ALGORITHM_EC");
		TA_add_ec_curve(&params_t, key_size);
	}
	DMSG("key_algorithm=%d key_rsa_public_exponent=%lu",
			key_algorithm, key_rsa_public_exponent);
	//Newly-generated key's characteristics divided appropriately
	//into hardware-enforced and software-enforced lists
	//(except APPLICATION_ID and APPLICATION_DATA)
	res = TA_fill_characteristics(&characts, &params_t,
							&characts_size);
	if (res != KM_ERROR_OK)
		goto exit;

	key_buffer_size = TA_get_key_size(key_algorithm);

	key_blob.key_material_size = characts_size + key_buffer_size
			+ TAG_LENGTH;

	key_material = TEE_Malloc(key_blob.key_material_size,
						TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key_material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	res = TA_generate_key(key_algorithm, key_size, key_material, key_digest,
			key_rsa_public_exponent);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to generate key, res=%x", res);
		goto exit;
	}

	//TODO add bind keys to operating system and patch level version

	TA_serialize_param_set(key_material + key_buffer_size, &params_t);

	res = TA_encrypt(key_material, key_blob.key_material_size);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to encrypt key blob, res=%x", res);
		goto exit;
	}
	key_blob.key_material = key_material;

exit:
	out += TA_serialize_rsp_err(out, &res);
	if (res == KM_ERROR_OK) {
		out += TA_serialize_key_blob_akms(out, &key_blob);
		out += TA_serialize_characteristics_akms(out, &characts);
	}
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;
	if (key_material)
		TEE_Free(key_material);
	TA_free_params(&characts.sw_enforced);
	TA_free_params(&characts.hw_enforced);
	TA_free_params(&params_t);

	return res;
}

//Return key parameters and characteristics associated during generation
static keymaster_error_t TA_getKeyCharacteristics(
					TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *key_material = NULL;
	keymaster_key_blob_t key_blob = EMPTY_KEY_BLOB;	/* IN */
	keymaster_blob_t client_id = EMPTY_BLOB;	/* IN */
	keymaster_blob_t app_data = EMPTY_BLOB;		/* IN */
	keymaster_key_characteristics_t chr = EMPTY_CHARACTS;	/* OUT */
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_error_t res = KM_ERROR_OK;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	uint32_t characts_size = 0;
	uint32_t key_size = 0;
	uint32_t type = 0;
	bool exportable = false;

	DMSG("%s %d", __func__, __LINE__);
	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_key_blob_akms(in, in_end, &key_blob, &res);
	if (res != KM_ERROR_OK)
		goto exit;
	in += TA_deserialize_blob_akms(in, in_end, &client_id, false, &res, false);
	if (res != KM_ERROR_OK)
		goto exit;
	in += TA_deserialize_blob_akms(in, in_end, &app_data, false, &res, false);
	if (res != KM_ERROR_OK)
		goto exit;
	if (key_blob.key_material_size == 0) {
		EMSG("Bad key blob");
		res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
		goto exit;
	}
	key_material = TEE_Malloc(key_blob.key_material_size,
						TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}
	res = TA_restore_key(key_material, &key_blob, &key_size, &type,
						 &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto exit;

	res = TA_check_permission(&params_t, client_id, app_data, &exportable);
	if (res != KM_ERROR_OK)
		goto exit;

	res = TA_fill_characteristics(&chr, &params_t, &characts_size);
	if (res != KM_ERROR_OK)
		goto exit;

exit:
	out += TA_serialize_rsp_err(out, &res);
	if (res == KM_ERROR_OK)
		out += TA_serialize_characteristics_akms(out, &chr);
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (key_blob.key_material)
		TEE_Free(key_blob.key_material);
	if (client_id.data)
		TEE_Free(client_id.data);
	if (app_data.data)
		TEE_Free(app_data.data);
	if (key_material)
		TEE_Free(key_material);
	TA_free_params(&chr.sw_enforced);
	TA_free_params(&chr.hw_enforced);
	TA_free_params(&params_t);

	return res;
}

//Imports key material into Keymaster hardware.
static keymaster_error_t TA_importKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;	/* IN */
	keymaster_key_format_t key_format = UNDEFINED;		/* IN */
	keymaster_blob_t key_data = EMPTY_BLOB;			/* IN */
	keymaster_key_blob_t key_blob = EMPTY_KEY_BLOB;/* OUT */
	keymaster_key_characteristics_t characts = EMPTY_CHARACTS;/* OUT */
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_algorithm_t key_algorithm = UNDEFINED;
	keymaster_digest_t key_digest = UNDEFINED;
	TEE_Attribute *attrs_in = NULL;
	uint8_t *key_material = NULL;
	uint32_t key_buffer_size = 0;
	uint32_t characts_size = 0;
	uint32_t key_size = UNDEFINED;
	uint32_t attrs_in_count = 0;
	uint64_t key_rsa_public_exponent = UNDEFINED;

	DMSG("%s %d", __func__, __LINE__);
	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_auth_set(in, in_end, &params_t, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	TA_add_origin(&params_t, KM_ORIGIN_IMPORTED, true);
	TEE_MemMove(&key_format, in, sizeof(key_format));
	in += TA_deserialize_key_format(in, in_end, &key_format, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob_akms(in, in_end, &key_data, false, &res, false);
	if (res != KM_ERROR_OK)
		goto out;

	//Parse mandatory and optional parameters
	res = TA_parse_params(params_t, &key_algorithm, &key_size,
					&key_rsa_public_exponent, &key_digest, true);
	if (res != KM_ERROR_OK)
		goto out;
	if (key_format == KM_KEY_FORMAT_RAW) {
		if (key_algorithm != KM_ALGORITHM_AES &&
				key_algorithm != KM_ALGORITHM_HMAC) {
			EMSG("Only HMAC and AES keys can imported in raw format");
			res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
//			goto out;
		}
		if (key_size == UNDEFINED)
			key_size = key_data.data_length * 8;
		if (key_algorithm == KM_ALGORITHM_HMAC) {
			res = TA_check_hmac_key_size(&key_data, &key_size, key_digest);
			if (res != KM_ERROR_OK) {
				EMSG("HMAC key check failed");
				goto out;
			}
		}
		if (key_algorithm == KM_ALGORITHM_HMAC && (key_size % 8 != 0 ||
						key_size > MAX_KEY_HMAC ||
						key_size < MIN_KEY_HMAC)) {
			EMSG("HMAC key size must be multiple of 8 in range from %d to %d",
						MIN_KEY_HMAC, MAX_KEY_HMAC);
			res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
			goto out;
		} else if (key_algorithm == KM_ALGORITHM_AES &&
				key_size != 128 && key_size != 192
				&& key_size != 256) {
			EMSG("Unsupported key size %d ! Supported only 128, 192 and 256",key_size);
			res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
			goto out;
		}

		attrs_in = TEE_Malloc(sizeof(TEE_Attribute),
							TEE_MALLOC_FILL_ZERO);
		if (!attrs_in) {
			EMSG("Failed to allocate memory for attributes");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto out;
		}
		attrs_in_count = 1;

		TEE_InitRefAttribute(attrs_in, TEE_ATTR_SECRET_VALUE,
				(void *) key_data.data, key_data.data_length);
	} else {/* KM_KEY_FORMAT_PKCS8 */
		if (key_algorithm != KM_ALGORITHM_RSA &&
				key_algorithm != KM_ALGORITHM_EC) {
			EMSG("Only TA_serialize_characteristicsRSA and EC keys can imported in PKCS8 fromat");
			res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
//			goto out;
		}

		res = mbedTLS_decode_pkcs8(key_data, &attrs_in,
					   &attrs_in_count, key_algorithm,
					   &key_size, &key_rsa_public_exponent);

		if (res != KM_ERROR_OK)
			goto out;
		if (key_algorithm == KM_ALGORITHM_RSA && (key_size % 8 != 0 ||
						key_size > MAX_KEY_RSA)) {
			EMSG("RSA key size must be multiple of 8 and less than %u",
								MAX_KEY_RSA);
			res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
			goto out;
		}
		if (key_algorithm == KM_ALGORITHM_RSA) {
			if (key_size > MAX_KEY_RSA) {
				EMSG("RSA key size must be multiple of 8 and less than %u",
								MAX_KEY_RSA);
				res = KM_ERROR_UNSUPPORTED_KEY_SIZE;
				goto out;
			}
		}
	}
	TA_add_to_params(&params_t, key_size, key_rsa_public_exponent);
	res = TA_fill_characteristics(&characts,
					&params_t, &characts_size);
	if (res != KM_ERROR_OK)
		goto out;
	key_buffer_size = TA_get_key_size(key_algorithm);
	key_blob.key_material_size = characts_size + key_buffer_size
			+ TAG_LENGTH;
	key_material = TEE_Malloc(key_blob.key_material_size,
						TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key_material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}

	res = TA_import_key(key_algorithm, key_size, key_material, key_digest,
						attrs_in, attrs_in_count);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to import key");
		goto out;
	}
	TA_serialize_param_set(key_material + key_buffer_size, &params_t);
	res = TA_encrypt(key_material, key_blob.key_material_size);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to encrypt blob");
		goto out;
	}
	key_blob.key_material = key_material;

out:
	out += TA_serialize_rsp_err(out, &res);
	if (res == KM_ERROR_OK) {
		out += TA_serialize_key_blob_akms(out, &key_blob);
		out += TA_serialize_characteristics_akms(out, &characts);
	}
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if ((key_data.data && key_format != KM_KEY_FORMAT_RAW) ||
		(key_data.data && key_format == KM_KEY_FORMAT_RAW && res != KM_ERROR_OK)) {
		TEE_Free(key_data.data);
	}

	free_attrs(attrs_in, attrs_in_count);
	TA_free_params(&params_t);
	TA_free_params(&characts.sw_enforced);
	TA_free_params(&characts.hw_enforced);
	if (key_material)
		TEE_Free(key_material);

	return res;
}

//Exports a public key from a Keymaster RSA or EC key pair.
static keymaster_error_t TA_exportKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	keymaster_key_format_t export_format = UNDEFINED;	/* IN */
	keymaster_key_blob_t key_to_export = EMPTY_KEY_BLOB;	/* IN */
	keymaster_key_param_set_t in_params = EMPTY_PARAM_SET;	/* IN */
	keymaster_blob_t export_data = EMPTY_BLOB;	/* OUT */
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	bool exportable = false;
	uint8_t *key_material = NULL;
	uint32_t key_size = UNDEFINED;
	uint32_t type = 0;

	DMSG("%s %d", __func__, __LINE__);
	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	//additional param
	in += TA_deserialize_auth_set(in, in_end, &in_params, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_key_format(in, in_end, &export_format, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_key_blob_akms(in, in_end, &key_to_export, &res);
	if (res != KM_ERROR_OK)
		goto out;

	//Keymaster supports export of public keys only in X.509 format
	if (export_format != KM_KEY_FORMAT_X509) {
		EMSG("Unsupported key export format");
		res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
		goto out;
	}
	key_material = TEE_Malloc(key_to_export.key_material_size,
						TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	res = TA_restore_key(key_material, &key_to_export, &key_size, &type,
						 &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	res = TA_check_permission(&params_t, in_params.params[0].key_param.blob/*client_id*/, in_params.params[1].key_param.blob/*app_data*/, &exportable);
	if (res != KM_ERROR_OK)
		goto out;
	if (!exportable && type != TEE_TYPE_RSA_KEYPAIR
			&& type != TEE_TYPE_ECDSA_KEYPAIR) {
		res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
		EMSG("This key type is not exportable");
		goto out;
	}
	res = mbedTLS_encode_key(&export_data, type, &obj_h);
	if (res != KM_ERROR_OK)
		goto out;

out:
	out += TA_serialize_rsp_err(out, &res);
	if (res == KM_ERROR_OK)
		out += TA_serialize_blob_akms(out, &export_data);
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (key_to_export.key_material)
		TEE_Free(key_to_export.key_material);
	if (key_material)
		TEE_Free(key_material);
	if (export_data.data)
		TEE_Free(export_data.data);
	TA_free_params(&params_t);
	TA_free_params(&in_params);

	return res;
}

static keymaster_error_t TA_attestKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint32_t out_size = 0;
	keymaster_key_blob_t key_to_attest = EMPTY_KEY_BLOB;/* IN */
	keymaster_key_param_set_t attest_params = EMPTY_PARAM_SET;/* IN */
	keymaster_cert_chain_t cert_chain = EMPTY_CERT_CHAIN;/* OUT */
	keymaster_error_t res = KM_ERROR_OK;
	TEE_Result result = TEE_SUCCESS;
	keymaster_blob_t *challenge = NULL;
	bool includeUniqueID = false;
	bool resetSinceIDRotation = false;
	keymaster_blob_t *app_id = NULL;
	keymaster_blob_t *app_data = NULL;
	keymaster_blob_t *attest_app_id = NULL;
	bool exportable = false;

	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	TEE_ObjectHandle attestedKey = TEE_HANDLE_NULL;
	uint8_t *key_material = NULL;
	uint32_t key_size = 0;
	uint32_t key_type = 0;

	keymaster_key_characteristics_t key_chr = EMPTY_CHARACTS;
	uint32_t key_chr_size = 0;
	uint8_t verified_boot_state = 0xff;

#ifdef ENUM_PERS_OBJS
	TA_enum_attest_objs();
#endif
#ifdef WIPE_PERS_OBJS
	TA_wipe_attest_objs();
#endif

	DMSG("%s %d", __func__, __LINE__);

#ifndef CFG_ATTESTATION_PROVISIONING
	//This call creates keys/certs only once during first TA run
	result = TA_create_attest_objs(sessionSTA);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to create attestation objects, res=%x", result);
		res = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}
#endif

	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;
	out_size = params[1].memref.size; //limited to 8192

	//Key blob for which the attestation will be created

	in += TA_deserialize_key_blob_akms(in, in_end, &key_to_attest, &res);
	if (res != KM_ERROR_OK)
		goto exit;

	if (key_to_attest.key_material_size == 0) {
			EMSG("Bad attestation key blob");
			res = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
			goto exit;
	}

	key_material = TEE_Malloc(key_to_attest.key_material_size,
						TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key material");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	//Deserialize parameters necessary for attestation
	in += TA_deserialize_auth_set(in, in_end, &attest_params, false, &res);
	if (res != KM_ERROR_OK)
		goto exit;
	verified_boot_state = *in;

	for (size_t i = 0; i < attest_params.length; i++) {
		switch (attest_params.params[i].tag) {
		case KM_TAG_APPLICATION_ID:
			app_id = &attest_params.params[i].key_param.blob;
			break;
		case KM_TAG_APPLICATION_DATA:
			app_data = &attest_params.params[i].key_param.blob;
			break;
		case KM_TAG_ATTESTATION_CHALLENGE:
			challenge = &attest_params.params[i].key_param.blob;
			if (challenge->data_length > MAX_ATTESTATION_CHALLENGE) {
				EMSG("Attestation challenge is too big");
				res = KM_ERROR_INVALID_INPUT_LENGTH;
				goto exit;
			}
			break;
		case KM_TAG_INCLUDE_UNIQUE_ID:
			includeUniqueID = attest_params.params[i].key_param.boolean;
			break;
		case KM_TAG_RESET_SINCE_ID_ROTATION:
			resetSinceIDRotation = attest_params.params[i].key_param.boolean;
			break;
		case KM_TAG_ATTESTATION_APPLICATION_ID:
			attest_app_id = &attest_params.params[i].key_param.blob;
			break;
		default:
			DMSG("Unused attestation parameter tag %x", attest_params.params[i].tag);
			break;
		}
	}

	(void)resetSinceIDRotation;
	if (challenge == NULL) {
		EMSG("Attestation challenge is missing");
		res = KM_ERROR_ATTESTATION_CHALLENGE_MISSING;
		goto exit;
	}
	if (attest_app_id == NULL) {
		EMSG("Attestation application ID is missing");
		res = KM_ERROR_ATTESTATION_APPLICATION_ID_MISSING;
		goto exit;
	}

	//Restore key
	res = TA_restore_key(key_material, &key_to_attest,
						&key_size, &key_type,
						&attestedKey, &params_t);
	if (res != KM_ERROR_OK)
		goto exit;

	if (app_id != NULL && app_data != NULL) {
		res = TA_check_permission(&params_t, *app_id, *app_data, &exportable);
		if (res != KM_ERROR_OK)
			goto exit;
	}

	//Check attested key type
	if (key_type != TEE_TYPE_RSA_KEYPAIR
			&& key_type != TEE_TYPE_ECDSA_KEYPAIR) {
		EMSG("Key attestation supports only asymmetric key pairs, type=%x", key_type);
		res = KM_ERROR_INCOMPATIBLE_ALGORITHM;
		goto exit;
	}

	res = TA_fill_characteristics(&key_chr, &params_t, &key_chr_size);
	if (res != KM_ERROR_OK)
		goto exit;

	if (includeUniqueID == true) {
		//TODO TA_generate_UniqueID(...);
	}

	//Read Root attestation certificate (must be generated and stored before)
	res = TA_read_root_attest_cert(key_type, &cert_chain);
	if (res != KM_ERROR_INSUFFICIENT_BUFFER_SPACE) {
		EMSG("Failed to get att cert chain len, res=%x", res);
		goto exit;
	}

	//Allocate memory for chain of certificates
	cert_chain.entries = TEE_Malloc(
			sizeof(keymaster_blob_t)*cert_chain.entry_count,
			TEE_MALLOC_FILL_ZERO);
	if (!cert_chain.entries) {
		EMSG("Failed to allocate memory for chain of certificates");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto exit;
	}

	//Read Root attestation certificate (must be generated and stored before)
	res = TA_read_root_attest_cert(key_type, &cert_chain);
	if (res != KM_ERROR_OK) {
		EMSG("Failed to read root att cert, res=%x", res);
		goto exit;
	}
	//Generate key attestation certificate (using STA ASN.1)
	result = TA_gen_key_attest_cert(sessionSTA, key_type, attestedKey,
				     &attest_params, &key_chr, &cert_chain,
				     verified_boot_state);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to gen key att cert, res=%x", result);
		res = KM_ERROR_UNKNOWN_ERROR;
		goto exit;
	}

	//Check output buffer length
	if (TA_cert_chain_size(&cert_chain) > out_size) {
		EMSG("Short output buffer for chain of certificates");
		res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto exit;
	}

exit:
	//Serialize output chain of certificates
	out += TA_serialize_rsp_err(out, &res);
	if (res == KM_ERROR_OK) {
		out += TA_serialize_cert_chain_akms(out, &cert_chain, &res);
	}
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if (key_to_attest.key_material)
		TEE_Free(key_to_attest.key_material);

	if (attestedKey != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(attestedKey);

	if (key_material)
		TEE_Free(key_material);

	TA_free_params(&attest_params);
	TA_free_params(&key_chr.sw_enforced);
	TA_free_params(&key_chr.hw_enforced);
	TA_free_params(&params_t);
	TA_free_cert_chain(&cert_chain);

	return res;
}

static keymaster_error_t TA_upgradeKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	keymaster_key_blob_t key_to_upgrade = EMPTY_KEY_BLOB;/* IN */
	keymaster_key_param_set_t upgr_params = EMPTY_PARAM_SET;/* IN */
	keymaster_key_blob_t upgraded_key = EMPTY_KEY_BLOB;/* OUT */
	keymaster_error_t res = KM_ERROR_OK;

	DMSG("%s %d", __func__, __LINE__);
	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_key_blob_akms(in, in_end, &key_to_upgrade, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_auth_set(in, in_end, &upgr_params, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	TA_add_origin(&upgr_params, KM_ORIGIN_UNKNOWN, false);

out:
	/* TODO Upgrade Key */
	out += TA_serialize_rsp_err(out, &res);
	if (res == KM_ERROR_OK)
		out += TA_serialize_key_blob_akms(out, &upgraded_key);
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	TA_free_params(&upgr_params);
	if (key_to_upgrade.key_material)
		TEE_Free(key_to_upgrade.key_material);
	return res;
}

//Deletes the provided key
static keymaster_error_t TA_deleteKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *out = NULL;
	keymaster_error_t res = KM_ERROR_OK;

	DMSG("%s %d", __func__, __LINE__);
	out = (uint8_t *) params[1].memref.buffer;
	out += TA_serialize_rsp_err(out, &res);
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	return res;
}

//Deletes all keys
static keymaster_error_t TA_deleteAllKeys(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *out = NULL;
	keymaster_error_t res = KM_ERROR_OK;

	DMSG("%s %d", __func__, __LINE__);
	out = (uint8_t *) params[1].memref.buffer;
	out += TA_serialize_rsp_err(out, &res);
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	return res;
}

//Permanently disable the ID attestation feature.
static keymaster_error_t TA_destroyAttestationIds(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *out = NULL;
	keymaster_error_t res = KM_ERROR_OK;

	DMSG("%s %d", __func__, __LINE__);
	out = (uint8_t *) params[1].memref.buffer;
	out += TA_serialize_rsp_err(out, &res);
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;
	/* TODO Delete all keys */
	return KM_ERROR_OK;
}

//Begins a cryptographic operation, using the specified key, for the specified purpose,
//with the specified parameters (as appropriate), and returns an operation handle that
//is used with update and finish to complete the operation.
static keymaster_error_t TA_begin(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	uint8_t *key_material = NULL;
	uint8_t *secretIV = NULL;
	uint32_t mac_length = UNDEFINED;
	uint32_t key_size = 0;
	uint32_t IVsize = UNDEFINED;
	uint32_t min_sec = UNDEFINED;
	uint32_t type = 0;
	bool do_auth = false;
	keymaster_purpose_t purpose = UNDEFINED;		/* IN */
	keymaster_key_blob_t key = EMPTY_KEY_BLOB;		/* IN */
	keymaster_key_param_set_t in_params = EMPTY_PARAM_SET;	/* IN */
	keymaster_key_param_set_t out_params = EMPTY_PARAM_SET;	/* OUT */
	keymaster_operation_handle_t operation_handle = 0;	/* OUT */
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_key_param_t *nonce_param = NULL;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_algorithm_t algorithm = UNDEFINED;
	keymaster_blob_t nonce = EMPTY_BLOB;
	keymaster_digest_t digest = UNDEFINED;
	keymaster_block_mode_t mode = UNDEFINED;
	keymaster_padding_t padding = UNDEFINED;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	TEE_OperationHandle *operation = TEE_HANDLE_NULL;
	TEE_OperationHandle *digest_op = TEE_HANDLE_NULL;
	uint8_t key_id[TAG_LENGTH];

	DMSG("%s %d", __func__, __LINE__);
	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	/* Freed when operation is aborted (TA_abort_operation) */
	operation = TEE_Malloc(sizeof(TEE_OperationHandle),
					TEE_MALLOC_FILL_ZERO);
	if (!operation) {
		EMSG("Failed to allocate memory for operation");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	/* Freed when operation is aborted (TA_abort_operation) */
	digest_op = TEE_Malloc(sizeof(TEE_OperationHandle),
					TEE_MALLOC_FILL_ZERO);
	if (!digest_op) {
		EMSG("Failed to allocate memory for digest operation");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	*operation = TEE_HANDLE_NULL;
	*digest_op = TEE_HANDLE_NULL;

	in += TA_deserialize_purpose(in, in_end, &purpose, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_key_blob_akms(in, in_end, &key, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_auth_set(in, in_end, &in_params, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	key_material = TEE_Malloc(key.key_material_size, TEE_MALLOC_FILL_ZERO);

	memcpy(key_id, key.key_material + key.key_material_size - TAG_LENGTH,
	       TAG_LENGTH);

	res = TA_restore_key(key_material, &key, &key_size,
						 &type, &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	switch (type) {
	case TEE_TYPE_AES:
		algorithm = KM_ALGORITHM_AES;
		break;
	case TEE_TYPE_RSA_KEYPAIR:
		algorithm = KM_ALGORITHM_RSA;
		break;
	case TEE_TYPE_ECDSA_KEYPAIR:
		algorithm = KM_ALGORITHM_EC;
		break;
	default:/* HMAC */
		algorithm = KM_ALGORITHM_HMAC;
	}
	res = TA_check_params(&params_t, &in_params,
				&algorithm, purpose, &digest, &mode,
				&padding, &mac_length, &nonce,
				&min_sec, &do_auth, key_id);
	if (res != KM_ERROR_OK)
		goto out;
	if (algorithm == KM_ALGORITHM_AES && mode !=
		    KM_MODE_ECB && nonce.data_length == 0) {
		if (mode == KM_MODE_CBC || mode == KM_MODE_CTR) {
			IVsize = 16;
		} else {/* GCM mode */
			IVsize = 12;
		}
		out_params.length = 1;
		secretIV = TEE_Malloc(IVsize, TEE_MALLOC_FILL_ZERO);
		if (!secretIV) {
			EMSG("Failed to allocate memory for secretIV");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto out;
		}
		nonce_param = TEE_Malloc(sizeof(keymaster_key_param_t), TEE_MALLOC_FILL_ZERO);
		if (!nonce_param) {
			TEE_Free(secretIV);
			EMSG("Failed to allocate memory for parameters");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto out;
		}
		TEE_GenerateRandom(secretIV, IVsize);
		nonce_param->tag = KM_TAG_NONCE;
		nonce_param->key_param.blob.data = secretIV;
		nonce_param->key_param.blob.data_length = IVsize;
		out_params.params = nonce_param;
		nonce.data_length = IVsize;
		nonce.data = secretIV;
	}

	res = TA_create_operation(operation, obj_h, purpose,
				algorithm, key_size, nonce,
				digest, mode, padding, mac_length);
	if (res != KM_ERROR_OK)
		goto out;

	TEE_GenerateRandom(&operation_handle, sizeof(operation_handle));
	if (purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_VERIFY ||
			(algorithm == KM_ALGORITHM_RSA &&
			padding == KM_PAD_RSA_PSS)) {
		res = TA_create_digest_op(digest_op, digest);
		if (res != KM_ERROR_OK)
			goto out;
	}
	res = TA_start_operation(operation_handle, key, min_sec,
				 operation, purpose, digest_op, do_auth,
				 padding, mode, mac_length, digest,
				 nonce, key_id);
	if (res != KM_ERROR_OK)
		goto out;

out:
	out += TA_serialize_rsp_err(out, &res);
	if (res == KM_ERROR_OK) {
		TEE_MemMove(out, &operation_handle, sizeof(operation_handle));
		out += sizeof(operation_handle);
		out += TA_serialize_auth_set(out, &out_params);
	}
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (key.key_material)
		TEE_Free(key.key_material);
	if (res != KM_ERROR_OK) {
		if (*digest_op != TEE_HANDLE_NULL)
			TEE_FreeOperation(*digest_op);
		if (*operation != TEE_HANDLE_NULL)
			TEE_FreeOperation(*operation);
		TEE_Free(operation);
		TEE_Free(digest_op);
	}
	if (key_material)
		TEE_Free(key_material);
	TA_free_params(&in_params);
	TA_free_params(&params_t);
	TA_free_params(&out_params);
	return res;
}

//Provides data to process in an ongoing operation started with begin.
static keymaster_error_t TA_update(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	keymaster_operation_handle_t operation_handle = 0;		/* IN */
	keymaster_key_param_set_t in_params = EMPTY_PARAM_SET;	/* IN */
	keymaster_blob_t input = EMPTY_BLOB;	/* IN */
	size_t input_consumed = 0;	/* OUT */
	keymaster_key_param_set_t out_params = EMPTY_PARAM_SET;	/* OUT */
	keymaster_blob_t output = EMPTY_BLOB;	/* OUT */
	uint8_t *key_material = NULL;
	uint32_t key_size = 0;
	uint32_t type = 0;
	uint32_t out_size = 0;
	uint32_t input_provided = 0;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_operation_t operation = EMPTY_OPERATION;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	bool is_input_ext = false;

	DMSG("%s %d", __func__, __LINE__);
	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_op_handle(in, in_end, &operation_handle, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob_akms(in, in_end, &input, false, &res, true);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_auth_set(in, in_end, &in_params, false, &res);
	if (res != KM_ERROR_OK)
		goto out;

	input_provided = input.data_length;
	res = TA_get_operation(operation_handle, &operation);
	if (res != KM_ERROR_OK)
		goto out;
	key_material = TEE_Malloc(operation.key->key_material_size,
						TEE_MALLOC_FILL_ZERO);
	res = TA_restore_key(key_material, operation.key, &key_size,
						 &type, &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	if (operation.do_auth) {
		res = TA_do_auth(in_params, params_t);
		if (res != KM_ERROR_OK) {
			EMSG("Authentication failed");
			goto out;
		}
	}

	if (input.data_length != 0 && type == TEE_TYPE_RSA_KEYPAIR)
		operation.got_input = true;
	out_size = TA_possibe_size(type, key_size, input, 0);
	output.data = TEE_Malloc(out_size, TEE_MALLOC_FILL_ZERO);
	if (!output.data) {
		EMSG("Failed to allocate memory for output");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	switch (type) {
	case TEE_TYPE_AES:
		res = TA_aes_update(&operation, &input, &output, &out_size,
					input_provided, &input_consumed,
					&in_params, &is_input_ext);
		break;
	case TEE_TYPE_RSA_KEYPAIR:
		res = TA_rsa_update(&operation, &input, &output, &out_size,
					key_size, &input_consumed,
					input_provided, obj_h);
		break;
	case TEE_TYPE_ECDSA_KEYPAIR:
		res = TA_ec_update(&operation, &input, &output,
					&input_consumed, input_provided);
		break;
	default:/* HMAC */
		TEE_MACUpdate(*operation.operation,
			input.data, input.data_length);
		input_consumed = input_provided;
	}
	if (res != KM_ERROR_OK) {
		EMSG("Update operation failed with error code %x", res);
		goto out;
	}

out:
	out += TA_serialize_rsp_err(out, &res);
	if (res == KM_ERROR_OK) {
		out += TA_serialize_blob_akms(out, &output);
		TEE_MemMove(out, &input_consumed, SIZE_LENGTH_AKMS);
		out += SIZE_LENGTH_AKMS;
		out += TA_serialize_auth_set(out, &out_params);
		TA_update_operation(operation_handle, &operation);
	}
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	if (input.data && is_input_ext)
		TEE_Free(input.data);
	if (output.data)
		TEE_Free(output.data);
	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (key_material)
		TEE_Free(key_material);
	if (res != KM_ERROR_OK)
		TA_abort_operation(operation_handle);
	TA_free_params(&params_t);
	TA_free_params(&in_params);
	TA_free_params(&out_params);
	return res;
}

//Finishes an ongoing operation started with begin, processing all
//of the as-yet-unprocessed data provided by update(s).
static keymaster_error_t TA_finish(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	keymaster_operation_handle_t operation_handle = 0;		/* IN */
	keymaster_key_param_set_t in_params = EMPTY_PARAM_SET;	/* IN */
	keymaster_blob_t input = EMPTY_BLOB;		/* IN */
	keymaster_blob_t signature = EMPTY_BLOB;		/* IN */
	keymaster_key_param_set_t out_params = EMPTY_PARAM_SET;/* OUT */
	keymaster_blob_t output = EMPTY_BLOB;		/* OUT */
	uint8_t *key_material = NULL;
	uint32_t key_size = 0;
	uint32_t type = 0;
	uint32_t out_size = 0;
	uint32_t tag_len = 0;
	keymaster_error_t res = KM_ERROR_OK;
	keymaster_key_param_set_t params_t = EMPTY_PARAM_SET;
	keymaster_operation_t operation = EMPTY_OPERATION;
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;
	bool is_input_ext = false;

	DMSG("%s %d", __func__, __LINE__);
	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_op_handle(in, in_end, &operation_handle, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob_akms(in, in_end, &signature, false, &res, false);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_auth_set(in, in_end, &in_params, false, &res);
	if (res != KM_ERROR_OK)
		goto out;
	in += TA_deserialize_blob_akms(in, in_end, &input, false, &res, true);
	if (res != KM_ERROR_OK)
		goto out;

	res = TA_get_operation(operation_handle, &operation);
	if (res != KM_ERROR_OK)
		goto out;
	key_material = TEE_Malloc(operation.key->key_material_size,
					TEE_MALLOC_FILL_ZERO);
	res = TA_restore_key(key_material, operation.key, &key_size, &type,
						 &obj_h, &params_t);
	if (res != KM_ERROR_OK)
		goto out;
	if (operation.do_auth) {
		res = TA_do_auth(in_params, params_t);
		if (res != KM_ERROR_OK) {
			EMSG("Authentication failed");
			goto out;
		}
	}
	if (type == TEE_TYPE_AES && operation.mode == KM_MODE_GCM)
		tag_len = operation.mac_length / 8;/* from bits to bytes */

	out_size = TA_possibe_size(type, key_size, input, tag_len);
	output.data = TEE_Malloc(out_size, TEE_MALLOC_FILL_ZERO);
	if (!output.data) {
		EMSG("Failed to allocate memory for output");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	switch (type) {
	case TEE_TYPE_AES:
		res = TA_aes_finish(&operation, &input, &output, &out_size,
					tag_len, &is_input_ext, &in_params);
		break;
	case TEE_TYPE_RSA_KEYPAIR:
		res = TA_rsa_finish(&operation, &input, &output, &out_size,
				key_size, signature, obj_h, &is_input_ext);
		break;
	case TEE_TYPE_ECDSA_KEYPAIR:
		res = TA_ec_finish(&operation, &input, &output, &signature,
					&out_size, key_size, &is_input_ext);
		break;
	default: /* HMAC */
		if (operation.purpose == KM_PURPOSE_SIGN) {
			TEE_MACComputeFinal(*operation.operation,
						input.data,
						input.data_length,
						output.data,
						&out_size);
			/*Trim out size to KM_TAG_MAC_LENGTH*/
			if (operation.mac_length != UNDEFINED) {
				if (out_size > operation.mac_length / 8) {
					DMSG("Trim HMAC out size to %d", operation.mac_length);
					out_size = operation.mac_length / 8;
				}
			}
		} else {/* KM_PURPOSE_VERIFY */
			res = TEE_MACCompareFinal(*operation.operation,
						input.data,
						input.data_length,
						signature.data,
						signature.data_length);
			out_size = 0;
			/* Convert error code to Android style */
			if (res == (int) TEE_ERROR_MAC_INVALID)
				res = KM_ERROR_VERIFICATION_FAILED;
		}
	}
	if (res != TEE_SUCCESS) {
		EMSG("Finish operation failed with error code %x", res);
		goto out;
	}
	output.data_length = out_size;

out:
	out += TA_serialize_rsp_err(out, &res);
	if (res == KM_ERROR_OK) {
		out += TA_serialize_blob_akms(out, &output);
		out += TA_serialize_auth_set(out, &out_params);
	}
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;

	TA_abort_operation(operation_handle);
	if (input.data && is_input_ext)
		TEE_Free(input.data);
	if (output.data)
		TEE_Free(output.data);
	if (signature.data)
		TEE_Free(signature.data);
	if (obj_h != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(obj_h);
	if (key_material)
		TEE_Free(key_material);
	TA_free_params(&params_t);
	TA_free_params(&in_params);
	TA_free_params(&out_params);
	return res;
}

//Aborts the in-progress operation
static keymaster_error_t TA_abort(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	uint8_t *out = NULL;
	keymaster_error_t res =  KM_ERROR_OK;
	keymaster_operation_handle_t operation_handle = 0;		/* IN */

	DMSG("%s %d", __func__, __LINE__);
	in = (uint8_t *) params[0].memref.buffer;
	in_end = in + params[0].memref.size;
	out = (uint8_t *) params[1].memref.buffer;

	in += TA_deserialize_op_handle(in, in_end, &operation_handle, &res);
	if (res != KM_ERROR_OK)
		goto out;
	res = TA_abort_operation(operation_handle);
out:
	out += TA_serialize_rsp_err(out, &res);
	params[1].memref.size = out - (uint8_t *)params[1].memref.buffer;
	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __unused,
			uint32_t cmd_id, uint32_t param_types,
			TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		EMSG("Keystore TA wrong parameters");
		return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
	}

	switch(cmd_id) {
	//Keymaster commands:
	case KM_CONFIGURE:
		DMSG("KM_CONFIGURE");
		return TA_configure(params);
	case KM_ADD_RNG_ENTROPY:
		DMSG("KM_ADD_RNG_ENTROPY");
		return TA_addRngEntropy(params);
	case KM_GENERATE_KEY:
		DMSG("KM_GENERATE_KEY");
		return TA_generateKey(params);
	case KM_GET_KEY_CHARACTERISTICS:
		DMSG("KM_GET_KEY_CHARACTERISTICS");
		return TA_getKeyCharacteristics(params);
	case KM_IMPORT_KEY:
		DMSG("KM_IMPORT_KEY");
		return TA_importKey(params);
	case KM_EXPORT_KEY:
		DMSG("KM_EXPORT_KEY");
		return TA_exportKey(params);
	case KM_ATTEST_KEY:
		DMSG("KM_ATTEST_KEY");
		return TA_attestKey(params);
	case KM_UPGRADE_KEY:
		DMSG("KM_UPGRADE_KEY");
		return TA_upgradeKey(params);
	case KM_DELETE_KEY:
		DMSG("KM_DELETE_KEY");
		return TA_deleteKey(params);
	case KM_DELETE_ALL_KEYS:
		DMSG("KM_DELETE_ALL_KEYS");
		return TA_deleteAllKeys(params);
	case KM_DESTROY_ATT_IDS:
		DMSG("KM_DESTROY_ATT_IDS");
		return TA_destroyAttestationIds(params);
	case KM_BEGIN:
		DMSG("KM_BEGIN");
		return TA_begin(params);
	case KM_UPDATE:
		DMSG("KM_UPDATE");
		return TA_update(params);
	case KM_FINISH:
		DMSG("KM_FINISH");
		return TA_finish(params);
	case KM_ABORT:
		DMSG("KM_ABORT");
		return TA_abort(params);
#ifdef CFG_ATTESTATION_PROVISIONING
	//Provisioning commands:
	case KM_SET_ATTESTATION_KEY:
		DMSG("KM_SET_ATTESTATION_KEY");
		return TA_SetAttestationKey(params);
	case KM_APPEND_ATTESTATION_CERT_CHAIN:
		DMSG("KM_APPEND_ATTESTATION_CERT_CHAIN");
		return TA_AppendAttestationCertKey(params);
#endif
	//Gatekeeper commands:
	case KM_GET_AUTHTOKEN_KEY:
		DMSG("KM_GET_AUTHTOKEN_KEY");
		return TA_GetAuthTokenKey(params);

	default:
		DMSG("Unknown command %d",cmd_id);
		return KM_ERROR_UNIMPLEMENTED;
	}
}
