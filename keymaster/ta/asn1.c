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

#include <mbedtls/x509.h>

#include "asn1.h"
#include "attestation.h"


static unsigned int get_key_usage(keymaster_key_param_t *param)
{
	unsigned int key_usage = 0;

	if (param->tag != KM_TAG_PURPOSE) {
		DMSG("Unused parameter tag %x", param->tag);
		return 0;
	}

	DMSG("key purpose 0x%08X",param->key_param.enumerated);
	if ((param->key_param.enumerated == KM_PURPOSE_VERIFY) ||
		(param->key_param.enumerated == KM_PURPOSE_SIGN))
	{
		key_usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
	}
	if ((param->key_param.enumerated == KM_PURPOSE_ENCRYPT) ||
		(param->key_param.enumerated == KM_PURPOSE_DECRYPT))
	{
		key_usage |= MBEDTLS_X509_KU_KEY_ENCIPHERMENT | MBEDTLS_X509_KU_DATA_ENCIPHERMENT;
	}

	return key_usage;
}

static unsigned int add_key_usage(keymaster_key_characteristics_t *key_chr)
{
	unsigned int key_usage = 0;

	for (size_t i = 0; i < key_chr->hw_enforced.length; i++) {
		key_usage |= get_key_usage(&(key_chr->hw_enforced.params[i]));
	}

	return key_usage;
}

keymaster_error_t TA_decode_pkcs8(const TEE_TASessionHandle sessionSTA,
				keymaster_blob_t key_data,
				TEE_Attribute **attrs,
				uint32_t *attrs_count,
				const keymaster_algorithm_t algorithm,
				uint32_t *key_size,
				uint64_t *rsa_public_exponent)
{
	uint8_t *buf = NULL;
	uint8_t *output = NULL;
	uint32_t output_size = 8 * 1024;
	uint32_t max_attrs = 0;
	uint32_t tag = 0;
	uint32_t padding = 0;
	uint32_t attr_size = 0;
	uint32_t *attrs_list = TA_get_attrs_list_short(algorithm, true);
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT);
	TEE_Param params[TEE_NUM_PARAMS];

	output = TEE_Malloc(output_size, TEE_MALLOC_FILL_ZERO);
	if (!output) {
		EMSG("Failed to allocate memory for ASN.1 parser output");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	params[2].memref.buffer = output;
	params[2].memref.size = output_size;
	params[1].value.a = algorithm;
	params[0].memref.buffer = key_data.data;
	params[0].memref.size = key_data.data_length;
	if (sessionSTA == TEE_HANDLE_NULL) {
		EMSG("Session with static TA is not opened");
		res = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
		goto out;
	}
	res = TEE_InvokeTACommand(sessionSTA, TEE_TIMEOUT_INFINITE,
			CMD_ASN1_DECODE, exp_param_types, params, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Invoke command for ASN.1 parser failed, res=%x", res);
		goto out;
	}
	if (params[2].memref.size == 0) {
		EMSG("ASN.1 parser output is empty");
		res = KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
		goto out;
	}
	if (*key_size == UNDEFINED)
		*key_size = params[3].value.a;
	if (algorithm == KM_ALGORITHM_RSA)
		max_attrs = KM_ATTR_COUNT_RSA;
	else
		max_attrs = KM_ATTR_COUNT_EC;
	*attrs = TEE_Malloc(sizeof(TEE_Attribute) * max_attrs,
							TEE_MALLOC_FILL_ZERO);
	if (!(*attrs)) {
		EMSG("Failed to allocate memory for attributes on key import");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	while (*attrs_count < max_attrs) {
		if (padding > params[2].memref.size) {
			EMSG("Failed to get all key params from ASN.1 parser");
			res = KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
			goto out;
		}
		tag = attrs_list[*attrs_count];
		TEE_MemMove(&attr_size, output + padding, sizeof(attr_size));
		padding += sizeof(attr_size);
		buf = TEE_Malloc(attr_size, TEE_MALLOC_FILL_ZERO);
		if (!buf) {
			EMSG("Failed to allocate memory for imported attribute buffer");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto out;
		}
		TEE_MemMove(buf, output + padding, attr_size);
		padding += attr_size;
		if (algorithm == KM_ALGORITHM_RSA && *attrs_count == 1 &&
					*rsa_public_exponent == UNDEFINED)
			TEE_MemMove(rsa_public_exponent, buf, attr_size);
		TEE_InitRefAttribute(*attrs + *attrs_count,
				tag, buf, attr_size);
		(*attrs_count)++;
		if (algorithm == KM_ALGORITHM_EC && *attrs_count == max_attrs - 1)
			/* the Curve attribute is defined later */
			break;
	}
out:
	if (output)
		TEE_Free(output);
	return res;
}

keymaster_error_t TA_encode_ec_sign(const TEE_TASessionHandle sessionSTA,
				uint8_t *out, uint32_t *out_l)
{
	uint32_t r_size = *out_l / 2;
	uint32_t s_size = *out_l / 2;
	uint8_t r[r_size];
	uint8_t s[s_size];
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t exp_param_types = TEE_PARAM_TYPES(
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	TEE_Param params[TEE_NUM_PARAMS];

	TEE_MemMove(r, out, r_size);
	TEE_MemMove(s, out + r_size, s_size);
	params[2].memref.buffer = out;
	params[2].memref.size = 0;
	params[1].memref.buffer = s;
	params[1].memref.size = s_size;
	params[0].memref.buffer = r;
	params[0].memref.size = r_size;
	if (sessionSTA == TEE_HANDLE_NULL) {
		EMSG("Session with static TA is not opened");
		res = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
		goto out;
	}
	res = TEE_InvokeTACommand(sessionSTA, TEE_TIMEOUT_INFINITE,
				CMD_EC_SIGN_ENCODE, exp_param_types,
				params, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Invoke command for ASN.1 parser (EC sign) failed, res=%x",
		     res);
		goto out;
	}
	if (params[2].memref.size == 0) {
		EMSG("ASN.1 parser (EC sign) output is empty");
		res = KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
		goto out;
	}
out:
	*out_l = params[2].memref.size;
	return res;
}

keymaster_error_t TA_encode_key(const TEE_TASessionHandle sessionSTA,
				keymaster_blob_t *export_data,
				const uint32_t type,
				const TEE_ObjectHandle *obj_h,
				const uint32_t key_size)
{
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t attr1_l = KM_RSA_ATTR_SIZE;
	uint32_t attr2_l = KM_RSA_ATTR_SIZE;
	uint8_t *attr1 = TEE_Malloc(attr1_l, TEE_MALLOC_FILL_ZERO);
	uint8_t *attr2 = TEE_Malloc(attr2_l, TEE_MALLOC_FILL_ZERO);
	uint8_t *output = NULL;
	uint32_t output_size = 1024;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT);
	TEE_Param params[TEE_NUM_PARAMS];

	if (!attr1 || !attr2) {
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		EMSG("Failed to allocate memory for local buffers");
		goto out;
	}
	if (type == TEE_TYPE_RSA_KEYPAIR) {
		res = TEE_GetObjectBufferAttribute(*obj_h,
					TEE_ATTR_RSA_MODULUS, attr1, &attr1_l);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get modulus attribute, res = %x", res);
			goto out;
		}
		res = TEE_GetObjectBufferAttribute(*obj_h,
				TEE_ATTR_RSA_PUBLIC_EXPONENT, attr2, &attr2_l);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get public exponent attribute, res = %x",
			     res);
			goto out;
		}
	} else {
		res = TEE_GetObjectBufferAttribute(*obj_h,
				TEE_ATTR_ECC_PUBLIC_VALUE_X, attr1, &attr1_l);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get public X attribute, res = %x", res);
			goto out;
		}
		res = TEE_GetObjectBufferAttribute(*obj_h,
				TEE_ATTR_ECC_PUBLIC_VALUE_Y, attr2, &attr2_l);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get public Y attribute, res = %x", res);
			goto out;
		}
	}
	output = TEE_Malloc(output_size, TEE_MALLOC_FILL_ZERO);
	if (!output) {
		EMSG("Failed to allocate memory for x.509 buffer");
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	params[3].memref.buffer = output;
	params[3].memref.size = output_size;
	params[2].value.a = type;
	params[2].value.b = key_size;
	params[1].memref.buffer = attr2;
	params[1].memref.size = attr2_l;
	params[0].memref.buffer = attr1;
	params[0].memref.size = attr1_l;

	if (sessionSTA == TEE_HANDLE_NULL) {
		EMSG("Session with static TA is not opened");
		res = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
		goto out;
	}
	res = TEE_InvokeTACommand(sessionSTA, TEE_TIMEOUT_INFINITE,
			CMD_ASN1_ENCODE_PUBKEY, exp_param_types, params, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Invoke command for x.509 ASN.1 encoder failed, res=%x",
		     res);
		goto out;
	}
	if (params[3].memref.size == 0) {
		EMSG("x.509 ASN.1 encoder output is empty");
		res = KM_ERROR_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM;
		goto out;
	}

	export_data->data_length = params[3].memref.size;
	export_data->data = TEE_Malloc(export_data->data_length,
							TEE_MALLOC_FILL_ZERO);
	if (!export_data->data) {
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		EMSG("Failed to allocate memory for x.509 output");
		goto out;
	}
	TEE_MemMove(export_data->data, params[3].memref.buffer,
					export_data->data_length);

out:
	if (attr1)
		TEE_Free(attr1);
	if (attr2)
		TEE_Free(attr2);
	if (output)
		TEE_Free(output);

	return res;
}

TEE_Result TA_gen_root_rsa_cert(const TEE_TASessionHandle sessionSTA __unused,
				TEE_ObjectHandle root_rsa_key,
				keymaster_blob_t *root_cert)
{
	return mbedTLS_gen_root_cert_rsa(root_rsa_key, root_cert);
}

TEE_Result TA_gen_root_ec_cert(const TEE_TASessionHandle sessionSTA __unused,
				TEE_ObjectHandle root_ec_key,
				keymaster_blob_t *root_cert)
{
	return mbedTLS_gen_root_cert_ecc(root_ec_key, root_cert);
}

TEE_Result TA_gen_attest_rsa_cert(const TEE_TASessionHandle sessionSTA,
		TEE_ObjectHandle attestedKey,
		keymaster_key_param_set_t *attest_params,
		keymaster_key_characteristics_t *key_chr,
		keymaster_cert_chain_t *cert_chain,
		uint8_t verified_boot)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle rootAttKey = TEE_HANDLE_NULL;
	keymaster_blob_t attest_ext = EMPTY_BLOB;
	unsigned int key_usage = 0;

	//Attested public key
	uint32_t attest_key_attr_size = (RSA_MAX_KEY_BUFFER_SIZE + sizeof(uint32_t)) * 2;
	uint8_t *attest_key_attr = TEE_Malloc(attest_key_attr_size, TEE_MALLOC_FILL_ZERO);

	//Attested parameters + Key characteristics in format: size | buffer | size | buffer
	uint32_t key_chr_attr_size = TA_characteristics_size(key_chr);
	uint32_t att_param_size = TA_param_set_size(attest_params);
	uint8_t *key_chr_attr = TEE_Malloc(key_chr_attr_size + att_param_size +
						sizeof(uint32_t) * 2 + 1,
					   TEE_MALLOC_FILL_ZERO);

	//Output certificate
	uint32_t output_certificate_size = ATTEST_CERT_BUFFER_SIZE;
	uint8_t *output_certificate = TEE_Malloc(output_certificate_size, TEE_MALLOC_FILL_ZERO);

	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, //attest pub key in format: size | buffer, ...
						TEE_PARAM_TYPE_MEMREF_INPUT,  //key characteristics + params in format: size | buffer, ...
						TEE_PARAM_TYPE_MEMREF_OUTPUT, //certificate
						TEE_PARAM_TYPE_NONE);
	TEE_Param params[TEE_NUM_PARAMS];

	uint8_t *tmp_keys_attr_buf = TEE_Malloc(RSA_MAX_KEY_BUFFER_SIZE, TEE_MALLOC_FILL_ZERO);
	uint32_t keys_attr_buf_size = RSA_MAX_KEY_BUFFER_SIZE;

	if (!attest_key_attr || !key_chr_attr ||
		!output_certificate || !tmp_keys_attr_buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		EMSG("Failed to allocate memory for local buffers");
		goto error_1;
	}

	if (sessionSTA == TEE_HANDLE_NULL) {
		EMSG("Session with static TA is not opened");
		res = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
		goto error_1;
	}

	key_usage = add_key_usage(key_chr);

	//Serialize attested key public attributes
	attest_key_attr_size = 0;
	keys_attr_buf_size = RSA_MAX_KEY_BUFFER_SIZE;
	res = TEE_GetObjectBufferAttribute(attestedKey,
				TEE_ATTR_RSA_MODULUS, tmp_keys_attr_buf, &keys_attr_buf_size);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get modulus attribute, res=%x", res);
		goto error_1;
	}

	TEE_MemMove(&attest_key_attr[attest_key_attr_size], &keys_attr_buf_size, sizeof(uint32_t));
	attest_key_attr_size += sizeof(uint32_t);
	TEE_MemMove(&attest_key_attr[attest_key_attr_size], tmp_keys_attr_buf, keys_attr_buf_size);
	attest_key_attr_size += keys_attr_buf_size;

	keys_attr_buf_size = RSA_MAX_KEY_BUFFER_SIZE;
	res = TEE_GetObjectBufferAttribute(attestedKey,
			TEE_ATTR_RSA_PUBLIC_EXPONENT, tmp_keys_attr_buf, &keys_attr_buf_size);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get public exponent attribute, res=%x", res);
		goto error_1;
	}

	TEE_MemMove(&attest_key_attr[attest_key_attr_size], &keys_attr_buf_size, sizeof(uint32_t));
	attest_key_attr_size += sizeof(uint32_t);
	TEE_MemMove(&attest_key_attr[attest_key_attr_size], tmp_keys_attr_buf, keys_attr_buf_size);
	attest_key_attr_size += keys_attr_buf_size;

	//Serialize attested key characteristics
	TEE_MemMove(&key_chr_attr[0], &key_chr_attr_size, sizeof(uint32_t));
	TA_serialize_characteristics(&key_chr_attr[sizeof(uint32_t)], key_chr);
	//Serialize attestation parameters
	TEE_MemMove(&key_chr_attr[sizeof(uint32_t) + key_chr_attr_size], &att_param_size, sizeof(uint32_t));
	TA_serialize_param_set(&key_chr_attr[sizeof(uint32_t) * 2 + key_chr_attr_size], attest_params);

	key_chr_attr[sizeof(uint32_t) * 2 + key_chr_attr_size + att_param_size]
	             = verified_boot;

	//Serialize root RSA attestation key (for sign)
	res = TA_open_rsa_attest_key(&rootAttKey);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open root RSA attestation key, res=%x", res);
		goto error_1;
	}

	///Link to command params
	params[0].memref.buffer = attest_key_attr;
	params[0].memref.size = attest_key_attr_size;

	params[1].memref.buffer = key_chr_attr;
	params[1].memref.size = key_chr_attr_size + att_param_size + sizeof(uint32_t) * 2;

	params[2].memref.buffer = output_certificate;
	params[2].memref.size = output_certificate_size;

	//Invoke command
	res = TEE_InvokeTACommand(sessionSTA, TEE_TIMEOUT_INFINITE,
			CMD_ASN1_GEN_ATT_EXTENSION, param_types, params, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to invoke ASN.1 command GEN_ATT_RSA_CERT, res=%x", res);
		goto error_1;
	}

	if (params[2].memref.size == 0) {
		EMSG("ASN.1 CMD_ASN1_GEN_ATT_EXTENSION output is empty");
		res = KM_ERROR_UNKNOWN_ERROR;
		goto error_1;
	}

	DMSG("attestation extension: \n");
	DHEXDUMP(params[2].memref.buffer,
		 params[2].memref.size);

	attest_ext.data = params[2].memref.buffer;
	attest_ext.data_length = params[2].memref.size;

	cert_chain->entries[KEY_ATT_CERT_INDEX].data_length = output_certificate_size;
	cert_chain->entries[KEY_ATT_CERT_INDEX].data = TEE_Malloc(output_certificate_size, TEE_MALLOC_FILL_ZERO);
	if (cert_chain->entries[KEY_ATT_CERT_INDEX].data == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		EMSG("Failed to allocate memory for attest certificate output");
		goto error_1;
	}

	res = mbedTLS_gen_attest_key_cert_rsa(rootAttKey,
					attestedKey,
					key_usage,
					cert_chain,
					&attest_ext);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to generate key attestation, res=%x", res);
		goto error_1;
	}

	DMSG("mbedTLS certificate: \n");
	DHEXDUMP(cert_chain->entries[KEY_ATT_CERT_INDEX].data,
		 cert_chain->entries[KEY_ATT_CERT_INDEX].data_length);

error_1:
	if (attest_key_attr) {
		TEE_Free(attest_key_attr);
	}
	if (key_chr_attr) {
		TEE_Free(key_chr_attr);
	}
	if (output_certificate) {
		TEE_Free(output_certificate);
	}
	if (tmp_keys_attr_buf) {
		TEE_Free(tmp_keys_attr_buf);
	}
	TA_close_attest_obj(rootAttKey);

	return res;
}

TEE_Result TA_gen_attest_ec_cert(const TEE_TASessionHandle sessionSTA,
		TEE_ObjectHandle attestedKey,
		keymaster_key_param_set_t *attest_params,
		keymaster_key_characteristics_t *key_chr,
		keymaster_cert_chain_t *cert_chain,
		uint8_t verified_boot)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle rootAttKey = TEE_HANDLE_NULL;
	keymaster_blob_t attest_ext = EMPTY_BLOB;
	unsigned int key_usage = 0;

	//Attested public key
	uint32_t attest_key_attr_size =
		(EC_MAX_KEY_BUFFER_SIZE + sizeof(uint32_t)) * 2 +
		2 * sizeof(uint32_t);
	uint8_t *attest_key_attr = TEE_Malloc(attest_key_attr_size, TEE_MALLOC_FILL_ZERO);

	//Attested parameters + Key characteristics in format: size | buffer | size | buffer
	uint32_t key_chr_attr_size = TA_characteristics_size(key_chr);
	uint32_t att_param_size = TA_param_set_size(attest_params);
	uint8_t *key_chr_attr = TEE_Malloc(key_chr_attr_size + att_param_size +
						sizeof(uint32_t) * 2 + 1,
					   TEE_MALLOC_FILL_ZERO);

	//Output certificate
	uint32_t output_certificate_size = ATTEST_CERT_BUFFER_SIZE;
	uint8_t *output_certificate = TEE_Malloc(output_certificate_size, TEE_MALLOC_FILL_ZERO);

	uint32_t param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, //attest pub key in format: size | buffer, ...
						TEE_PARAM_TYPE_MEMREF_INPUT,  //key characteristics + params in format: size | buffer, ...
						TEE_PARAM_TYPE_MEMREF_OUTPUT, //certificate
						TEE_PARAM_TYPE_NONE); 
	TEE_Param params[TEE_NUM_PARAMS];

	uint8_t *tmp_keys_attr_buf = TEE_Malloc(EC_MAX_KEY_BUFFER_SIZE, TEE_MALLOC_FILL_ZERO);
	uint32_t keys_attr_buf_size = EC_MAX_KEY_BUFFER_SIZE;
	uint32_t a = 0, b = 0, a_size = sizeof(uint32_t);

	if (!attest_key_attr || !key_chr_attr
			|| !output_certificate || !tmp_keys_attr_buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		EMSG("Failed to allocate memory for local buffers");
		goto error_1;
	}

	if (sessionSTA == TEE_HANDLE_NULL) {
		EMSG("Session with static TA is not opened");
		res = KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
		goto error_1;
	}

	key_usage = add_key_usage(key_chr);

	//Serialize attested key public attributes
	attest_key_attr_size = 0;
	keys_attr_buf_size = EC_MAX_KEY_BUFFER_SIZE;

	res = TEE_GetObjectValueAttribute(attestedKey, TEE_ATTR_ECC_CURVE, &a, &b);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get curve attribute, res=%x", res);
		goto error_1;
	}
	TEE_MemMove(&attest_key_attr[attest_key_attr_size], &a_size, sizeof(uint32_t));
	attest_key_attr_size += sizeof(uint32_t);
	TEE_MemMove(&attest_key_attr[attest_key_attr_size], &a, sizeof(uint32_t));
	attest_key_attr_size += sizeof(uint32_t);

	res = TEE_GetObjectBufferAttribute(attestedKey,
			TEE_ATTR_ECC_PUBLIC_VALUE_X, tmp_keys_attr_buf, &keys_attr_buf_size);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get public X attribute, res=%x", res);
		goto error_1;
	}
	TEE_MemMove(&attest_key_attr[attest_key_attr_size], &keys_attr_buf_size, sizeof(uint32_t));
	attest_key_attr_size += sizeof(uint32_t);
	TEE_MemMove(&attest_key_attr[attest_key_attr_size], tmp_keys_attr_buf, keys_attr_buf_size);
	attest_key_attr_size += keys_attr_buf_size;

	keys_attr_buf_size = EC_MAX_KEY_BUFFER_SIZE;
	res = TEE_GetObjectBufferAttribute(attestedKey,
			TEE_ATTR_ECC_PUBLIC_VALUE_Y, tmp_keys_attr_buf, &keys_attr_buf_size);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get public public Y attribute, res=%x", res);
		goto error_1;
	}
	TEE_MemMove(&attest_key_attr[attest_key_attr_size], &keys_attr_buf_size, sizeof(uint32_t));
	attest_key_attr_size += sizeof(uint32_t);
	TEE_MemMove(&attest_key_attr[attest_key_attr_size], tmp_keys_attr_buf, keys_attr_buf_size);
	attest_key_attr_size += keys_attr_buf_size;
	//Serialize attested key characteristics
	TEE_MemMove(&key_chr_attr[0], &key_chr_attr_size, sizeof(uint32_t));
	TA_serialize_characteristics(&key_chr_attr[sizeof(uint32_t)], key_chr);
	//Serialize attestation parameters
	TEE_MemMove(&key_chr_attr[sizeof(uint32_t) + key_chr_attr_size], &att_param_size, sizeof(uint32_t));
	TA_serialize_param_set(&key_chr_attr[sizeof(uint32_t) * 2 + key_chr_attr_size], attest_params);

	key_chr_attr[sizeof(uint32_t) * 2 + key_chr_attr_size + att_param_size]
	             = verified_boot;

	//Serialize root EC attestation key (for sign)
	res = TA_open_ec_attest_key(&rootAttKey);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open root EC attestation key, res=%x", res);
		goto error_1;
	}

	///Link to command params
	params[0].memref.buffer = attest_key_attr;
	params[0].memref.size = attest_key_attr_size;

	params[1].memref.buffer = key_chr_attr;
	params[1].memref.size = key_chr_attr_size + att_param_size + sizeof(uint32_t) * 2;

	params[2].memref.buffer = output_certificate;
	params[2].memref.size = output_certificate_size;

	//Invoke command
	res = TEE_InvokeTACommand(sessionSTA, TEE_TIMEOUT_INFINITE,
			CMD_ASN1_GEN_ATT_EXTENSION, param_types, params, NULL);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to invoke ASN.1 command GEN_ATT_EC_CERT, res=%x", res);
		goto error_1;
	}

	if (params[2].memref.size == 0) {
		EMSG("ASN.1 CMD_ASN1_GEN_ATT_EXTENSION output is empty");
		res = KM_ERROR_UNKNOWN_ERROR;
		goto error_1;
	}

	DMSG("attestation extension: \n");
	DHEXDUMP(params[2].memref.buffer,
		 params[2].memref.size);

	attest_ext.data = params[2].memref.buffer;
	attest_ext.data_length = params[2].memref.size;

	cert_chain->entries[KEY_ATT_CERT_INDEX].data_length = output_certificate_size;
	cert_chain->entries[KEY_ATT_CERT_INDEX].data = TEE_Malloc(output_certificate_size, TEE_MALLOC_FILL_ZERO);
	if (cert_chain->entries[KEY_ATT_CERT_INDEX].data == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		EMSG("Failed to allocate memory for attest certificate output");
		goto error_1;
	}

	res = mbedTLS_gen_attest_key_cert_ecc(rootAttKey,
					attestedKey,
					key_usage,
					cert_chain,
					&attest_ext);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to generate key attestation, res=%x", res);
		goto error_1;
	}

	DMSG("mbedTLS certificate: \n");
	DHEXDUMP(cert_chain->entries[KEY_ATT_CERT_INDEX].data,
		 cert_chain->entries[KEY_ATT_CERT_INDEX].data_length);

error_1:
	if (attest_key_attr) {
		TEE_Free(attest_key_attr);
	}
	if (key_chr_attr) {
		TEE_Free(key_chr_attr);
	}
	if (output_certificate) {
		TEE_Free(output_certificate);
	}
	if (tmp_keys_attr_buf) {
		TEE_Free(tmp_keys_attr_buf);
	}
	TA_close_attest_obj(rootAttKey);

	return res;
}
