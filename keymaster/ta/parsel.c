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
int TA_deserialize_blob_akms(uint8_t *in, const uint8_t *end,
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
	if (IS_OUT_OF_BOUNDS(in, end, SIZE_LENGTH_AKMS)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return in - start;
	}
	TEE_MemMove(&blob->data_length, in, SIZE_LENGTH_AKMS);
	in += SIZE_LENGTH_AKMS;
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


static bool param_deserialize(keymaster_key_param_t* param, uint8_t** buf_ptr, const uint8_t* end,
                        const uint8_t* indirect_base, const uint8_t* indirect_end)
{
    uint32_t offset;
    uint8_t *data;

	//param_set tag
    TEE_MemMove(&param->tag, *buf_ptr, sizeof(param->tag));
	*buf_ptr += sizeof(param->tag);

	DMSG("param tag:0x%x", param->tag);
	//param_set content
    switch (keymaster_tag_get_type(param->tag)) {
    case KM_INVALID:
        return false;
    case KM_ENUM:
    case KM_ENUM_REP:
        TEE_MemMove(&param->key_param.enumerated, *buf_ptr, sizeof(param->key_param.enumerated));
		*buf_ptr += sizeof(param->key_param.enumerated);
		break;
    case KM_UINT:
    case KM_UINT_REP:
        TEE_MemMove(&param->key_param.integer, *buf_ptr, sizeof(param->key_param.integer));
		*buf_ptr += sizeof(param->key_param.integer);
		break;
    case KM_ULONG:
    case KM_ULONG_REP:
        TEE_MemMove(&param->key_param.long_integer, *buf_ptr, sizeof(param->key_param.long_integer));
		*buf_ptr += sizeof(param->key_param.long_integer);
		break;
    case KM_DATE:
        TEE_MemMove(&param->key_param.date_time, *buf_ptr, sizeof(param->key_param.date_time));
		*buf_ptr += sizeof(param->key_param.date_time);
        break;
    case KM_BOOL:
        if (*buf_ptr < end) {
            param->key_param.boolean = (bool)(**buf_ptr);
            (*buf_ptr)++;
            return true;
        }
        return false;

    case KM_BIGNUM:
    case KM_BYTES: {
        TEE_MemMove(&param->key_param.blob.data_length, *buf_ptr, sizeof(uint32_t));
		*buf_ptr += sizeof(uint32_t);
        TEE_MemMove(&offset, *buf_ptr, sizeof(offset));
		*buf_ptr += sizeof(uint32_t);
        if (((param->key_param.blob.data_length + offset) < param->key_param.blob.data_length) ||  // Overflow check
            (offset > (indirect_end - indirect_base)) ||
            ((offset + param->key_param.blob.data_length) > (unsigned long)(indirect_end - indirect_base))) {
            DMSG("blob params deserialize err");
            return false;
        }

        if ((indirect_base != NULL) && (param->key_param.blob.data_length != 0)) {
            /* Freed when deserialized blob is destroyed by caller */
            data = TEE_Malloc(param->key_param.blob.data_length, TEE_MALLOC_FILL_ZERO);
            if (!data) {
                EMSG("Failed to allocate memory for blob");
                return false;
            }
            TEE_MemMove(data, indirect_base + offset, param->key_param.blob.data_length);
            param->key_param.blob.data = data;
            DMSG("type blob, blob_data:%p, blob len:%ld", param->key_param.blob.data, param->key_param.blob.data_length);
        }
		//data_length(uint32_t) and offset(uint32_t)
        return true;
	    }
	default:
		break;
    }

    return false;
}


int TA_deserialize_auth_set(uint8_t *in, const uint8_t *end,
			keymaster_key_param_set_t *param_set,
			const bool check_presence, keymaster_error_t *res)
{
	const uint8_t *start = in;
	presence p = KM_POPULATED;
	uint32_t indirect_data_size = 0;
	uint32_t elem_serialized_size = 0;
	uint8_t * indirect_base = NULL;
	const uint8_t * indirect_end;

	DMSG("%s %d", __func__, __LINE__);
	TEE_MemFill(param_set, 0, sizeof(*param_set));
	if (check_presence) {
		if (IS_OUT_OF_BOUNDS(in, end, sizeof(p))) {
			EMSG("Out of input array bounds on deserialization");
			*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
			goto out;
		}
		TEE_MemMove(&p, in, sizeof(p));
		in += sizeof(p);
	}
	if (p == KM_NULL)
		goto out;

	//Size of indirect_data_(uint32_t)
	if (IS_OUT_OF_BOUNDS(in, end, SIZE_LENGTH_AKMS)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto out;
	}
	TEE_MemMove(&indirect_data_size, in, sizeof(indirect_data_size));
	in += SIZE_LENGTH_AKMS;

	//indirect_data_, todo
	DMSG("indirect_data_size:%d", indirect_data_size);
	/* Freed when deserialized blob is destroyed by caller */
	indirect_base = TEE_Malloc(indirect_data_size, TEE_MALLOC_FILL_ZERO);
	if (!indirect_base) {
		EMSG("Failed to allocate memory for blob");
		*res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	DMSG("indirect_base:%p", indirect_base);
	TEE_MemMove(indirect_base, in, indirect_data_size);
	indirect_end = indirect_base + indirect_data_size;
	in += indirect_data_size;

	//Number of elems_(uint32_t)
	if (IS_OUT_OF_BOUNDS(in, end, SIZE_LENGTH_AKMS)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto out;
	}
	TEE_MemMove(&param_set->length, in, SIZE_LENGTH_AKMS);
	in += SIZE_LENGTH_AKMS;
	DMSG("elem cnt:%ld", param_set->length);

	//Size of elems_(uint32_t)
	if (IS_OUT_OF_BOUNDS(in, end, SIZE_LENGTH_AKMS)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		goto out;
	}
	TEE_MemMove(&elem_serialized_size, in, SIZE_LENGTH_AKMS);
	in += SIZE_LENGTH_AKMS;
	DMSG("elem serialized size:%d", elem_serialized_size);

	/* Do +3 to params count to have memory for
	 * adding KM_TAG_ORIGIN params and key size with RSA
	 * public exponent on import
	 */
	param_set->params = TEE_Malloc(sizeof(keymaster_key_param_t)
			* (param_set->length + ADDITIONAL_TAGS),
			TEE_MALLOC_FILL_ZERO);
	/* Freed when deserialized params set is destroyed by caller */
	if (!param_set->params) {
		EMSG("Failed to allocate memory for params");
		*res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	for (size_t i = 0; i < param_set->length; i++) {
		param_deserialize(&(param_set->params[i]), &in, end, indirect_base, indirect_end);
	}

out:
	//free indirect_base, data malloc and copy in param_deserialize
	if (indirect_base)
		TEE_Free(indirect_base);

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
			in += TA_deserialize_blob_akms(in, end,
				&(params->params[i].key_param.blob),
				false, res, false);
			if (*res != KM_ERROR_OK)
				return in - start;
		}
	}
	return in - start;
}

int TA_deserialize_key_blob_akms(const uint8_t *in, const uint8_t *end,
			keymaster_key_blob_t *key_blob,
			keymaster_error_t *res)
{
	uint8_t *key_material;

	DMSG("%s %d", __func__, __LINE__);
	if (IS_OUT_OF_BOUNDS(in, end, SIZE_LENGTH_AKMS)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return 0;
	}
	TEE_MemMove(&key_blob->key_material_size, in,
				SIZE_LENGTH_AKMS);
	DMSG("key_blob->key_material_size = %zu"
			"sizeof(key_blob->key_material_size) = %zu",
			key_blob->key_material_size,
			SIZE_LENGTH_AKMS);
	in += SIZE_LENGTH_AKMS;
	if (IS_OUT_OF_BOUNDS(in, end, key_blob->key_material_size)) {
		EMSG("Out of input array bounds on deserialization");
		*res = KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		return SIZE_LENGTH_AKMS;
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
	return KEY_BLOB_SIZE_AKMS(key_blob);
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
int TA_serialize_rsp_err(uint8_t *out, const keymaster_error_t *error)
{
	DMSG("res: %d", *error);
	TEE_MemMove(out, error, sizeof(*error));
	return sizeof(*error);
}

int TA_serialize_blob_akms(uint8_t *out, const keymaster_blob_t *blob)
{
	DMSG("%s %d", __func__, __LINE__);
	TEE_MemMove(out, &blob->data_length, SIZE_LENGTH_AKMS);
	out += SIZE_LENGTH_AKMS;
	TEE_MemMove(out, blob->data, blob->data_length);
	return BLOB_SIZE_AKMS(blob);
}

static uint8_t* param_serialize(const keymaster_key_param_t *param, uint8_t* buf, const uint8_t* indirect_base, uint8_t *addr_indirect_data)
{
	int32_t offset = 0;
    TEE_MemMove(buf, &param->tag, sizeof(param->tag));
	buf += sizeof(param->tag);
    switch (keymaster_tag_get_type(param->tag)) {
    case KM_INVALID:
        break;
    case KM_ENUM:
    case KM_ENUM_REP:
		TEE_MemMove(buf, &param->key_param.enumerated, sizeof(param->key_param.enumerated));
        buf += sizeof(param->key_param.enumerated);
        break;
    case KM_UINT:
    case KM_UINT_REP:
		TEE_MemMove(buf, &param->key_param.integer, sizeof(param->key_param.integer));
        buf += sizeof(param->key_param.integer);
        break;
    case KM_ULONG:
    case KM_ULONG_REP:
		TEE_MemMove(buf, &param->key_param.long_integer, sizeof(param->key_param.long_integer));
        buf += sizeof(param->key_param.long_integer);
        break;
    case KM_DATE:
		TEE_MemMove(buf, &param->key_param.date_time, sizeof(param->key_param.date_time));
        buf += sizeof(param->key_param.date_time);
        break;
    case KM_BOOL:
        *buf = (uint8_t)(param->key_param.boolean);
        buf++;
        break;
    case KM_BIGNUM:
    case KM_BYTES:
		TEE_MemMove(buf, &param->key_param.blob.data_length, SIZE_LENGTH_AKMS);
        buf += SIZE_LENGTH_AKMS;
		DMSG("blob len: %ld", param->key_param.blob.data_length);
		offset = addr_indirect_data - indirect_base;
		TEE_MemMove(buf, &offset, SIZE_LENGTH_AKMS);
		DMSG("blob offset: %d", offset);
        buf += SIZE_LENGTH_AKMS;
		if (offset < 0)
			EMSG("get error blob offset");
        break;
	default:
		break;
    }
    return buf;
}

int TA_serialize_auth_set(uint8_t *out,
			const keymaster_key_param_set_t *param_set)
{
	uint8_t *start = out;
	uint8_t *p_elems_size = NULL;
	uint32_t elems_size = 0;
	uint8_t *p_elems = NULL;
	uint8_t *indirect_data = NULL;
	uint32_t indirect_data_size = 0;
	uint32_t serialized_auth_set_size = 0;
	uint8_t **addr_indirect_data;

	DMSG("%s %d", __func__, __LINE__);

	//allocate mem for blob data offset in indirect_data
	addr_indirect_data = TEE_Malloc(param_set->length * sizeof(uint8_t *), TEE_MALLOC_FILL_ZERO);
	if (!addr_indirect_data) {
		EMSG("Failed to allocate memory for addr_indirect_data");
		return 0;
	}

	//indirect_data_size
	out += 4;
	//indirect_data
	indirect_data = out;
	for (size_t i = 0; i < param_set->length; i++) {
		if (keymaster_tag_get_type(param_set->params->tag) == KM_BIGNUM ||
				keymaster_tag_get_type(param_set->params->tag) == KM_BYTES) {
			TEE_MemMove(out, param_set->params->key_param.blob.data, param_set->params->key_param.blob.data_length);
			// set blob data new address for calculate offset in param_serialize
			addr_indirect_data[i] = out;
			out += param_set->params->key_param.blob.data_length;
			indirect_data_size += param_set->params->key_param.blob.data_length;
		}
	}
	//populate indirect_data_size
//		*(uint32_t *)start = indirect_data_size;	//alian issue
	TEE_MemMove(start, &indirect_data_size, SIZE_LENGTH_AKMS);

	DMSG("indirect_data_size: %d", indirect_data_size);

	//elems count
	TEE_MemMove(out, &param_set->length, SIZE_LENGTH_AKMS);
	out += SIZE_LENGTH_AKMS;
	DMSG("elems cnt: %ld", param_set->length);

	//elems size
	p_elems_size = out;
	out += SIZE_LENGTH_AKMS;

	p_elems = out;
	for (size_t i = 0; i < param_set->length; i++) {
		out = param_serialize(param_set->params + i, out, indirect_data, addr_indirect_data[i]);
	}

	//populate elems size
	elems_size = out - p_elems;
	TEE_MemMove(p_elems_size, &elems_size, SIZE_LENGTH_AKMS);
	DMSG("elems size: %d", elems_size);

    serialized_auth_set_size = sizeof(uint32_t) +           // Size of indirect_data_
       indirect_data_size +        // indirect_data_
       sizeof(uint32_t) +           // Number of elems_
       sizeof(uint32_t) +           // Size of elems_
       elems_size;  // elems_
    DMSG("auth_set size: %d", serialized_auth_set_size);

	TEE_Free(addr_indirect_data);
    return serialized_auth_set_size;
}

int TA_serialize_characteristics_akms(uint8_t *out,
			const keymaster_key_characteristics_t *characteristics)
{
	uint8_t *start = out;

	DMSG("%s %d", __func__, __LINE__);
	out += TA_serialize_auth_set(out, &(characteristics->hw_enforced));
	out += TA_serialize_auth_set(out, &(characteristics->sw_enforced));

	return out - start;
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
			out += TA_serialize_blob_akms(out, &(characteristics->
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
			out += TA_serialize_blob_akms(out, &((characteristics->
				sw_enforced.params + i)->key_param.blob));
		}
	}
	return out - start;
}

int TA_serialize_key_blob_akms(uint8_t *out, const keymaster_key_blob_t *key_blob)
{
	DMSG("%s %d", __func__, __LINE__);
	TEE_MemMove(out, &key_blob->key_material_size, SIZE_LENGTH_AKMS);
	out += SIZE_LENGTH_AKMS;
	TEE_MemMove(out, key_blob->key_material, key_blob->key_material_size);
	return KEY_BLOB_SIZE_AKMS(key_blob);
}

int TA_serialize_cert_chain_akms(uint8_t *out,
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
	out += SIZE_LENGTH_AKMS;

	for (size_t i = 0; i < cert_chain->entry_count; i++) {
		TEE_MemMove(out, &cert_chain->entries[i].data_length,
				SIZE_LENGTH_AKMS);
		out += SIZE_LENGTH_AKMS;

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
			out += TA_serialize_blob_akms(out,
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
	uint8_t tmp_key_attr_buf[RSA_MAX_KEY_BUFFER_SIZE];
	uint32_t key_attr_buf_size = RSA_MAX_KEY_BUFFER_SIZE;

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
		if (key_attr_buf_size > RSA_MAX_KEY_BUFFER_SIZE) {
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
	uint8_t tmp_key_attr_buf[EC_MAX_KEY_BUFFER_SIZE];
	uint32_t key_attr_buf_size = EC_MAX_KEY_BUFFER_SIZE;
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
		if (key_attr_buf_size > EC_MAX_KEY_BUFFER_SIZE) {
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
