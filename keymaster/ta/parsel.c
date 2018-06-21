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

#include "parsel.h"
#include "attestation.h"
#include "generator.h"

/* Deserializers */
int TA_deserialize_blob(uint8_t *in, const uint8_t *end,
			keymaster_blob_t *blob,
			const bool check_presence,
			keymaster_error_t *res,
			bool is_input)
{
	uint8_t *data;
	const uint8_t *start = in;
	presence p = KM_POPULATED;

	DMSG("%s %d", __func__, __LINE__);
	TEE_MemFill(blob, 0, sizeof(*blob));
	if (check_presence) {
		if (IS_OUT_OF_BOUNDS(in, end, sizeof(p))) {
			EMSG("Out of input array bounds on deserialization");
			*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			return in - start;
		}
		TEE_MemMove(&p, in, sizeof(p));
		in += sizeof(p);
	}
	if (p == KM_NULL)
		return sizeof(p);
	if (IS_OUT_OF_BOUNDS(in, end, SIZE_LENGTH)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return in - start;
	}
	TEE_MemMove(&blob->data_length, in, sizeof(blob->data_length));
	in += SIZE_LENGTH;
	if (IS_OUT_OF_BOUNDS(in, end, blob->data_length)) {
		EMSG("Out of input array bounds on deserialization %lu", blob->data_length);
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return in - start;
	}
	if (!is_input) {
		/* Freed when deserialized blob is destroyed by caller */
		data = TEE_Malloc(blob->data_length, TEE_MALLOC_FILL_ZERO);
		if (!data) {
			EMSG("Failed to allocate memory for blob");
			*res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			return in - start;
		}
		TEE_MemMove(data, in, blob->data_length);
		in += blob->data_length;
		blob->data = data;
	} else {
		/* Not allocate memory, it can be too large */
		blob->data = in;
		in += blob->data_length;
	}
	return in - start;
}

int TA_deserialize_param_set(uint8_t *in, const uint8_t *end,
			keymaster_key_param_set_t *params,
			const bool check_presence, keymaster_error_t *res)
{
	const uint8_t *start = in;
	presence p = KM_POPULATED;

	DMSG("%s %d", __func__, __LINE__);
	TEE_MemFill(params, 0, sizeof(*params));
	if (check_presence) {
		if (IS_OUT_OF_BOUNDS(in, end, sizeof(p))) {
			EMSG("Out of input array bounds on deserialization");
			*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			return in - start;
		}
		TEE_MemMove(&p, in, sizeof(p));
		in += sizeof(p);
	}
	if (p == KM_NULL)
		return in - start;
	if (IS_OUT_OF_BOUNDS(in, end, SIZE_LENGTH)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return in - start;
	}
	TEE_MemMove(&params->length, in, sizeof(params->length));
	in += SIZE_LENGTH;
	/* Do +3 to params count to have memory for
	 * adding KM_TAG_ORIGIN params and key size with RSA
	 * public exponent on import
	 */
	params->params = TEE_Malloc(sizeof(keymaster_key_param_t)
			* (params->length + ADDITIONAL_TAGS),
			TEE_MALLOC_FILL_ZERO);
	/* Freed when deserialized params set is destroyed by caller */
	if (!params->params) {
		EMSG("Failed to allocate memory for params");
		*res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		return in - start;
	}
	for (size_t i = 0; i < params->length; i++) {
		if (IS_OUT_OF_BOUNDS(in, end, SIZE_OF_ITEM(params->params))) {
			EMSG("Out of input array bounds on deserialization");
			*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			return in - start;
		}
		TEE_MemMove(params->params + i, in,
			SIZE_OF_ITEM(params->params));
		in += SIZE_OF_ITEM(params->params);
		if (keymaster_tag_get_type(params->params[i].tag)
				== KM_BIGNUM || keymaster_tag_get_type(
				params->params[i].tag) == KM_BYTES) {
			in += TA_deserialize_blob(in, end,
				&(params->params[i].key_param.blob),
				false, res, false);
			if (*res != KM_ERROR_OK)
				return in - start;
	}
	}
	return in - start;
}

int TA_deserialize_key_blob(const uint8_t *in, const uint8_t *end,
			keymaster_key_blob_t *key_blob,
			keymaster_error_t *res)
{
	uint8_t *key_material;

	DMSG("%s %d", __func__, __LINE__);
	if (IS_OUT_OF_BOUNDS(in, end, SIZE_LENGTH)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return 0;
	}
	TEE_MemMove(&key_blob->key_material_size, in,
				sizeof(key_blob->key_material_size));
	EMSG("%s %d key_blob->key_material_size = %zu sizeof(key_blob->key_material_size) = %zu",
			__func__, __LINE__, key_blob->key_material_size, sizeof(key_blob->key_material_size));
	in += SIZE_LENGTH;
	if (IS_OUT_OF_BOUNDS(in, end, key_blob->key_material_size)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return SIZE_LENGTH;
	}
	/* Freed when deserialized key blob is destroyed by caller */
	key_material = TEE_Malloc(key_blob->key_material_size,
							TEE_MALLOC_FILL_ZERO);
	if (!key_material) {
		EMSG("Failed to allocate memory for key_material");
		*res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		return 0;
	}
	TEE_MemMove(key_material, in, key_blob->key_material_size);
	key_blob->key_material = key_material;
	return KEY_BLOB_SIZE(key_blob);
}

int TA_deserialize_op_handle(const uint8_t *in, const uint8_t *in_end,
			keymaster_operation_handle_t *op_handle,
			keymaster_error_t *res)
{
	DMSG("%s %d", __func__, __LINE__);
	if (IS_OUT_OF_BOUNDS(in, in_end, sizeof(*op_handle))) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return 0;
	}
	TEE_MemMove(op_handle, in,
		sizeof(*op_handle));
	return sizeof(*op_handle);
}

int TA_deserialize_purpose(const uint8_t *in, const uint8_t *in_end,
			keymaster_purpose_t *purpose, keymaster_error_t *res)
{
	DMSG("%s %d", __func__, __LINE__);
	if (IS_OUT_OF_BOUNDS(in, in_end, sizeof(*purpose))) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return 0;
	}
	TEE_MemMove(purpose, in, sizeof(*purpose));
	return sizeof(*purpose);
}

int TA_deserialize_key_format(const uint8_t *in, const uint8_t *in_end,
			keymaster_key_format_t *key_format,
			keymaster_error_t *res)
{
	DMSG("%s %d", __func__, __LINE__);
	if (IS_OUT_OF_BOUNDS(in, in_end, sizeof(*key_format))) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return 0;
	}
	TEE_MemMove(key_format, in, sizeof(*key_format));
	return sizeof(*key_format);
}

/* Serializers */
int TA_serialize_blob(uint8_t *out, const keymaster_blob_t *blob)
{
	DMSG("%s %d", __func__, __LINE__);
	TEE_MemMove(out, &blob->data_length, sizeof(blob->data_length));
	out += SIZE_LENGTH;
	TEE_MemMove(out, blob->data, blob->data_length);
	return BLOB_SIZE(blob);
}

int TA_serialize_characteristics(uint8_t *out,
			const keymaster_key_characteristics_t *characteristics)
{
	uint8_t *start = out;

	DMSG("%s %d", __func__, __LINE__);
	TEE_MemMove(out, &characteristics->hw_enforced.length,
				sizeof(characteristics->hw_enforced.length));
	out += SIZE_LENGTH;
	for (size_t i = 0; i < characteristics->hw_enforced.length; i++) {
		TEE_MemMove(out, characteristics->hw_enforced.params + i,
			SIZE_OF_ITEM(characteristics->hw_enforced.params));
		out += SIZE_OF_ITEM(characteristics->hw_enforced.params);
		if (keymaster_tag_get_type(characteristics->
				hw_enforced.params[i].tag) == KM_BIGNUM ||
				keymaster_tag_get_type(characteristics->
				hw_enforced.params[i].tag) == KM_BYTES) {
			out += TA_serialize_blob(out, &(characteristics->
				hw_enforced.params[i].key_param.blob));
		}
	}

	TEE_MemMove(out, &characteristics->sw_enforced.length,
				sizeof(characteristics->sw_enforced.length));
	out += SIZE_LENGTH;
	for (size_t i = 0; i < characteristics->sw_enforced.length; i++) {
		TEE_MemMove(out, characteristics->sw_enforced.params + i,
			SIZE_OF_ITEM(characteristics->sw_enforced.params));
		out += SIZE_OF_ITEM(characteristics->sw_enforced.params);
		if (keymaster_tag_get_type(characteristics->
				sw_enforced.params[i].tag) == KM_BIGNUM ||
				keymaster_tag_get_type(characteristics->
				sw_enforced.params[i].tag) == KM_BYTES) {
			out += TA_serialize_blob(out, &((characteristics->
				sw_enforced.params + i)->key_param.blob));
		}
	}
	return out - start;
}

int TA_serialize_key_blob(uint8_t *out, const keymaster_key_blob_t *key_blob)
{
	DMSG("%s %d", __func__, __LINE__);
	TEE_MemMove(out, &key_blob->key_material_size,
				sizeof(key_blob->key_material_size));
	out += SIZE_LENGTH;
	TEE_MemMove(out, key_blob->key_material, key_blob->key_material_size);
	return KEY_BLOB_SIZE(key_blob);
}

int TA_serialize_cert_chain(uint8_t *out,
			const keymaster_cert_chain_t *cert_chain,
			keymaster_error_t *res)
{
	uint8_t *start = out;
	DMSG("%s %d", __func__, __LINE__);

	if (!cert_chain) {
		EMSG("Failed to allocate memory for certificate chain entries");
		*res = KM_ERROR_OUTPUT_PARAMETER_NULL;
		return 0;
	}

	TEE_MemMove(out, &cert_chain->entry_count,
				sizeof(cert_chain->entry_count));
	out += SIZE_LENGTH;

	for (size_t i = 0; i < cert_chain->entry_count; i++) {
		TEE_MemMove(out, &cert_chain->entries[i].data_length,
				sizeof(cert_chain->entries[i].data_length));
		out += SIZE_LENGTH;

		TEE_MemMove(out, cert_chain->entries[i].data,
				cert_chain->entries[i].data_length);
		out += cert_chain->entries[i].data_length;
	}
	*res = KM_ERROR_OK;
	return out - start;
}

int TA_serialize_param_set(uint8_t *out,
			const keymaster_key_param_set_t *params)
{
	uint8_t *start = out;
	DMSG("%s %d", __func__, __LINE__);
	TEE_MemMove(out, &params->length, sizeof(params->length));
	out += SIZE_LENGTH;

	for (size_t i = 0; i < params->length; i++) {
		TEE_MemMove(out, params->params + i,
				SIZE_OF_ITEM(params->params));
		out += SIZE_OF_ITEM(params->params);

		if (keymaster_tag_get_type(params->params[i].tag) == KM_BIGNUM
				|| keymaster_tag_get_type(params->
				params[i].tag) == KM_BYTES) {
			out += TA_serialize_blob(out,
				&(params->params[i].key_param.blob));
		}
	}
	return out - start;
}

//Serialize root RSA key-pair (public and private parts)
TEE_Result TA_serialize_rsa_keypair(uint8_t *out,
			uint32_t *out_size,
			const TEE_ObjectHandle key_obj)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t readSize = 0;
	uint8_t tmp_key_attr_buf[RSA_KEY_BUFFER_SIZE];
	uint32_t key_attr_buf_size = RSA_KEY_BUFFER_SIZE;

	DMSG("%s %d", __func__, __LINE__);
	//Read root RSA key attributes
	res = TEE_SeekObjectData(key_obj, 0, TEE_DATA_SEEK_SET);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to seek root RSA key, res=%x", res);
		return res;
	}

	*out_size = 0;
	//Public + Private parts:
	for (uint32_t i = 0; i < KM_ATTR_COUNT_RSA; i++) {
		res = TEE_ReadObjectData(key_obj, &key_attr_buf_size, sizeof(uint32_t),
				&readSize);
		if (res != TEE_SUCCESS || readSize != sizeof(uint32_t)) {
			EMSG("Failed to read RSA attribute size, res=%x", res);
			return res;
		}
		if (key_attr_buf_size > RSA_KEY_BUFFER_SIZE) {
			EMSG("Invalid RSA attribute size %d", key_attr_buf_size);
			res = TEE_ERROR_BAD_STATE;
			return res;
		}
		res = TEE_ReadObjectData(key_obj, tmp_key_attr_buf, key_attr_buf_size,
				&readSize);
		if (res != TEE_SUCCESS || readSize != key_attr_buf_size) {
			EMSG("Failed to read RSA attribute buffer, res=%x", res);
			return res;
		}
		TEE_MemMove(&out[*out_size], &key_attr_buf_size, sizeof(uint32_t));
		*out_size += sizeof(uint32_t);
		TEE_MemMove(&out[*out_size], tmp_key_attr_buf, key_attr_buf_size);
		*out_size += key_attr_buf_size;
	}

	return res;
}

TEE_Result TA_serialize_ec_keypair(uint8_t *out,
			uint32_t *out_size,
			const TEE_ObjectHandle key_obj)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t readSize = 0;
	uint8_t tmp_key_attr_buf[EC_KEY_BUFFER_SIZE];
	uint32_t key_attr_buf_size = EC_KEY_BUFFER_SIZE;
	uint32_t a = 0, a_size = sizeof(uint32_t);

	DMSG("%s %d", __func__, __LINE__);
	//Read EC key attributes
	res = TEE_SeekObjectData(key_obj, 0, TEE_DATA_SEEK_SET);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to seek root EC key, res=%x", res);
		return res;
	}

	*out_size = 0;
	//Public + Private parts:
	res = TEE_ReadObjectData(key_obj, &a, sizeof(uint32_t), &readSize);
	if (res != TEE_SUCCESS || readSize != sizeof(uint32_t)) {
		EMSG("Failed to read EC Curve, res=%x", res);
		return res;
	}

	TEE_MemMove(&out[*out_size], &a_size, sizeof(uint32_t));
	*out_size += sizeof(uint32_t);
	TEE_MemMove(&out[*out_size], &a, sizeof(uint32_t));
	*out_size += sizeof(uint32_t);

	for (uint32_t i = 0; i < (KM_ATTR_COUNT_EC - 1); i++) {//skip curve
		res = TEE_ReadObjectData(key_obj, &key_attr_buf_size,
				sizeof(uint32_t), &readSize);
		if (res != TEE_SUCCESS || readSize != sizeof(uint32_t)) {
			EMSG("Failed to read EC attribute size, res=%x", res);
			return res;
		}
		if (key_attr_buf_size > EC_KEY_BUFFER_SIZE) {
			EMSG("Invalid EC attribute size %d", key_attr_buf_size);
			res = TEE_ERROR_BAD_STATE;
			return res;
		}
		res = TEE_ReadObjectData(key_obj, tmp_key_attr_buf,
				key_attr_buf_size, &readSize);
		if (res != TEE_SUCCESS || readSize != key_attr_buf_size) {
			EMSG("Failed to read EC attribute buffer, res=%x", res);
			return res;
		}
		TEE_MemMove(&out[*out_size], &key_attr_buf_size, sizeof(uint32_t));
		*out_size += sizeof(uint32_t);
		TEE_MemMove(&out[*out_size], tmp_key_attr_buf, key_attr_buf_size);
		*out_size += key_attr_buf_size;
	}

	return res;
}
