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

#include "crypto_aes.h"

static bool TA_is_stream_cipher(const keymaster_block_mode_t mode)
{
	switch (mode) {
	case KM_MODE_CBC:
	case KM_MODE_ECB:
		return false;
	default:/*KM_MODE_GCM, KM_MODE_CTR*/
		return true;
	}
}

static void TA_append_tag(keymaster_blob_t *output, uint32_t *out_size,
			const uint8_t *tag, const uint32_t tag_len)
{
	/* is assumed that output has enough allocated memory */
	TEE_MemMove(output->data + *out_size, tag, tag_len);
	*out_size += tag_len;
}

static keymaster_error_t TA_append_input(keymaster_blob_t *input,
			keymaster_operation_t *operation,
			const uint32_t to_copy, bool *is_input_ext)
{
	uint8_t *data = NULL;
	uint32_t tag_length = operation->mac_length / 8;
	uint32_t push_to_input = operation->a_data_length
					+ to_copy - tag_length;

	data = TEE_Malloc(input->data_length + push_to_input,
						TEE_MALLOC_FILL_ZERO);
	if (!data) {
		EMSG("Failed to allocate memory for input appended by TAG");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	TEE_MemMove(data, operation->a_data, push_to_input);
	TEE_MemMove(data + push_to_input, input->data, input->data_length);
	if (*is_input_ext)
		TEE_Free(input->data);
	input->data = data;
	input->data_length += push_to_input;
	operation->a_data_length -= push_to_input;
	TEE_MemMove(operation->a_data, operation->a_data + push_to_input,
					operation->a_data_length);
	*is_input_ext = true;
	return KM_ERROR_OK;
}

static keymaster_error_t TA_save_gcm_tag(keymaster_blob_t *input,
				keymaster_operation_t *operation,
				bool *is_input_ext)
{
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t tag_size = operation->mac_length / 8;
	uint32_t to_copy = tag_size;

	if (input->data_length == 0)
		return res;
	if (input->data_length < tag_size)
		to_copy = input->data_length;
	if (operation->a_data_length + to_copy > tag_size) {
		res = TA_append_input(input, operation, to_copy, is_input_ext);
		if (res != KM_ERROR_OK)
			return res;
	}

	TEE_MemMove(operation->a_data + operation->a_data_length, input->data +
				(input->data_length - to_copy), to_copy);
	input->data_length -= to_copy;
	operation->a_data_length += to_copy;
	DMSG("Tag has been stored with size %u", operation->a_data_length);
	return res;
}

static keymaster_error_t TA_aes_gcm_prepare(keymaster_operation_t *operation,
				const keymaster_key_param_set_t *in_params,
				keymaster_blob_t *input, bool *is_input_ext)
{
	for (uint32_t i = 0; i < in_params->length; i++) {
		if (in_params->params[i].tag == KM_TAG_ASSOCIATED_DATA) {
			if (operation->got_input) {
				EMSG("KM_TAG_ASSOCIATED_DATA is found when input data has been received already");
				return KM_ERROR_INVALID_TAG;
			}
			TEE_AEUpdateAAD(*operation->operation,
				in_params->params[i].key_param.blob.data,
				in_params->params[i].key_param.blob.data_length);
			break;
		}
	}
	if (input->data_length != 0)
		operation->got_input = true;

	/* During AES GCM decryption, the last KM_TAG_MAC_LENGTH bytes
	 * of the data provided to the last update call is the tag
	 */
	if (operation->mac_length != UNDEFINED &&
			operation->purpose == KM_PURPOSE_DECRYPT &&
			input->data_length > 0) {
		if (operation->a_data == NULL) {
			/* Freed when operation is
			 * aborted (TA_abort_operation)
			 */
			operation->a_data = TEE_Malloc(operation->mac_length/8,
						TEE_MALLOC_FILL_ZERO);
			if (!operation->a_data) {
				EMSG("Failed to allocate memory for authentication tag");
				return KM_ERROR_MEMORY_ALLOCATION_FAILED;
			}
		}
		/* Since a given invocation of update cannot know if
		 * it's the last invocation, it must process all but
		 * the tag length and buffer the possible tag data
		 * for processing during finish.
		 */
		return TA_save_gcm_tag(input, operation, is_input_ext);
	}
	return KM_ERROR_OK;
}

keymaster_error_t TA_aes_finish(keymaster_operation_t *operation,
 				keymaster_blob_t *input,
 				keymaster_blob_t *output, uint32_t *out_size,
				uint32_t tag_len, bool *is_input_ext,
				const keymaster_key_param_set_t *in_params)
{
	TEE_Result tee_res = TEE_SUCCESS;
	keymaster_error_t res = KM_ERROR_OK;
	uint8_t *tag = NULL;

	if (operation->padding == KM_PAD_PKCS7 &&
			operation->purpose == KM_PURPOSE_ENCRYPT) {
		res = TA_add_pkcs7_pad(input, !operation->padded, output,
							out_size, is_input_ext);
		if (res != KM_ERROR_OK)
			goto out;
		operation->padded = true;
	} else if (operation->padding == KM_PAD_NONE && (operation->mode ==
			KM_MODE_CBC || operation->mode == KM_MODE_ECB) &&
			input->data_length % BLOCK_SIZE != 0) {
		EMSG("Input data size for AES CBC and ECB modes without padding must be a multiple of block size");
		res = KM_ERROR_INVALID_INPUT_LENGTH;
		goto out;
	} else if (operation->padding == KM_PAD_PKCS7 &&
			operation->purpose == KM_PURPOSE_DECRYPT &&
			input->data_length % BLOCK_SIZE != 0) {
		EMSG("Input data size for AES PKCS7 must be a multiple of block size");
		res = KM_ERROR_INVALID_INPUT_LENGTH;
		goto out;
	}
	if (operation->mode == KM_MODE_GCM) {
		/* For KM_MODE_GCM */
		res = TA_aes_gcm_prepare(operation, in_params, input, is_input_ext);
		if (res != KM_ERROR_OK)
			goto out;
		if (operation->purpose == KM_PURPOSE_ENCRYPT) {
			/* During encryption */
			tag = TEE_Malloc(tag_len, TEE_MALLOC_FILL_ZERO);
			if (!tag) {
				EMSG("Failed to allocate memory for GCM tag");
				res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
				goto out;
			}
			res = TEE_AEEncryptFinal(*operation->operation,
						input->data, input->data_length,
						output->data, out_size,
						tag, &tag_len);
			if (res != KM_ERROR_OK) {
				EMSG("TEE_AEEncryptFinal failed, res=%x", res);
				goto out;
			}
			/* after processing all plaintext, compute the
			 * tag (KM_TAG_MAC_LENGTH bytes) and append it
			 * to the returned ciphertext
			 */
			TA_append_tag(output, out_size, tag, tag_len);
		} else {/* KM_PURPOSE_DECRYPT	During decryption
			 * process the last KM_TAG_MAC_LENGTH bytes from
			 * input data of last Update as the tag
			 */
			tee_res = TEE_AEDecryptFinal(*operation->operation,
						input->data, input->data_length,
						output->data, out_size,
						operation->a_data, /*tag to compare*/
						operation->mac_length / 8);
			if (tee_res == TEE_ERROR_MAC_INVALID) {
				/* tag verification fails */
				EMSG("AES GCM verification failed, res=%x", res);
				res = KM_ERROR_VERIFICATION_FAILED;
				goto out;
			}
		}
	} else {
		res = TEE_CipherDoFinal(*operation->operation, input->data,
					input->data_length, output->data,
					out_size);
	}
	output->data_length = *out_size;
	if (res == KM_ERROR_OK && operation->padding == KM_PAD_PKCS7
			&& operation->purpose == KM_PURPOSE_DECRYPT) {
		if (output->data_length > 0) {
			res = TA_remove_pkcs7_pad(output, out_size);
			if (res == KM_ERROR_OK)
				operation->padded = true;
		}
		if (!operation->padded) {
			EMSG("Padding was not removed");
			res = KM_ERROR_INVALID_ARGUMENT;
		}
	}
out:
	if (tag)
		TEE_Free(tag);
	return res;
}

static keymaster_error_t TA_store_last_block(keymaster_blob_t *output,
					size_t *input_consumed,
					keymaster_operation_t *op)
{
	if (output->data_length < BLOCK_SIZE) {
		EMSG("Output is too smal to be stored");
		return KM_ERROR_UNKNOWN_ERROR;
	}
	op->last_block.data = TEE_Malloc(BLOCK_SIZE, TEE_MALLOC_FILL_ZERO);
	if (!op->last_block.data) {
		EMSG("Failed to allocate memory for last block buffer");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	TEE_MemMove(op->last_block.data, output->data +
		output->data_length - BLOCK_SIZE, BLOCK_SIZE);
	output->data_length -= BLOCK_SIZE;
	*input_consumed -= BLOCK_SIZE;
	op->prev_in_size += BLOCK_SIZE;
	op->last_block.data_length = BLOCK_SIZE;
	return KM_ERROR_OK;
}

static keymaster_error_t TA_restore_last_block(keymaster_blob_t *output,
					size_t *input_consumed,
					keymaster_operation_t *op,
					uint32_t *pos)
{
	if (op->last_block.data_length != BLOCK_SIZE) {
		EMSG("Stored block has a bad size");
		return KM_ERROR_UNKNOWN_ERROR;
	}
	TEE_MemMove(output->data, op->last_block.data, BLOCK_SIZE);
	*input_consumed += BLOCK_SIZE;
	*pos += BLOCK_SIZE;
	op->last_block.data_length = 0;
	TEE_Free(op->last_block.data);
	op->last_block.data = NULL;
	output->data_length += BLOCK_SIZE;
	return KM_ERROR_OK;
}

keymaster_error_t TA_aes_update(keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output,
				uint32_t *out_size,
				const uint32_t input_provided,
				size_t *input_consumed,
				const keymaster_key_param_set_t *in_params,
				bool *is_input_ext)
{
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t pos = 0U;
	uint32_t remainder = 0;
	uint32_t in_size = BLOCK_SIZE;

	/* KM_MODE_CBC, KM_MODE_ECB */
	if (!TA_is_stream_cipher(operation->mode)) {
		if (operation->last_block.data != NULL && operation->last_block.data_length != 0) {
			DMSG("Restore last block");
			res = TA_restore_last_block(output, input_consumed, operation, &pos);
			if (res != KM_ERROR_OK) {
				EMSG("Failed to restore last block");
				goto out;
			}
		}
		if (operation->padding == KM_PAD_PKCS7) {
			if (operation->prev_in_size == input->data_length) {
				DMSG("End of data reached");
				operation->buffering = false;
			} else {
				DMSG("Buffering ON");
				operation->buffering = true;
			}
			if (operation->prev_in_size == UNDEFINED
					&& input->data_length == BLOCK_SIZE) {
				operation->prev_in_size = input->data_length;
				goto out;
			}
			operation->prev_in_size = input->data_length;
			if (operation->buffering && ((input->data_length <=
					BLOCK_SIZE && operation->purpose ==
					KM_PURPOSE_DECRYPT) ||
					(input->data_length < BLOCK_SIZE &&
					operation->purpose ==
					KM_PURPOSE_ENCRYPT))) {
				DMSG("Input data is too small. Buffering");
				/* Buffering if data
				 * transferred by chunks
				 */
				goto out;
			}
			DMSG("Some blocks can be processed");
		} else {/* KM_PAD_NONE */
			if (input->data_length < BLOCK_SIZE)
				goto out;
		}
	}

	/* only KM_MODE_CBC and KM_MODE_ECB */
	if (operation->padding == KM_PAD_PKCS7 && !operation->buffering &&
			operation->purpose == KM_PURPOSE_ENCRYPT) {
		DMSG("Adding padding before encryption");
		res = TA_add_pkcs7_pad(input, !operation->padded, output,
					out_size, is_input_ext);
		if (res != KM_ERROR_OK)
			goto out;
		operation->padded = true;
	}
	remainder = input->data_length - pos;
	if (operation->mode == KM_MODE_GCM) {
		/* check presence of associated data for AES keys */
		res = TA_aes_gcm_prepare(operation, in_params, input,
								is_input_ext);
		if (res != KM_ERROR_OK)
			goto out;
		/* Resize output if input length increased */
		res = TA_check_out_size(input->data_length, output, out_size,
						operation->mac_length / 8);
		if (res != KM_ERROR_OK)
			goto out;
		res = TEE_AEUpdate(*operation->operation, input->data,
				input->data_length, output->data, out_size);
		if (res != KM_ERROR_OK)
			goto out;
		output->data_length += *out_size;
		*input_consumed = input_provided;
	} else {
		if (operation->mode == KM_MODE_CTR)
			/* CTR is a stream mode */
			in_size = input->data_length;
		while (operation->mode == KM_MODE_CTR
			   || remainder / BLOCK_SIZE != 0) {
			/* calculate memory left.
			 * Add BLOCK_SIZE in case adding padding
			 */
			*out_size = BLOCK_SIZE + input->data_length -
							output->data_length;
			res = TEE_CipherUpdate(*operation->operation,
					input->data + pos, in_size,
					output->data + pos, out_size);
			if (res != TEE_SUCCESS) {
				EMSG("Error TEE_CipherUpdate, res=%x", res);
				goto out;
			}
			output->data_length += *out_size;
			pos += in_size;
			*input_consumed += in_size;
			operation->prev_in_size -= in_size;
			remainder -= in_size;
			if (remainder < BLOCK_SIZE)
				break;
		}
	}
	if (*input_consumed > input_provided)
		*input_consumed = input_provided;
	if (res == KM_ERROR_OK && operation->padding == KM_PAD_PKCS7 &&
			operation->purpose == KM_PURPOSE_DECRYPT
			&& *input_consumed == input_provided) {
		if (operation->buffering && TA_check_pkcs7_pad(output)
						&& operation->first) {
			DMSG("Store last block");
			res = TA_store_last_block(output, input_consumed,
								operation);
			if (res != KM_ERROR_OK) {
				EMSG("Failed to store last block");
				goto out;
			}
		}
		if (!operation->buffering || TA_check_pkcs7_pad(output)) {
			DMSG("Remove PKCS7 pad");
			res = TA_remove_pkcs7_pad(output, out_size);
			if (res == KM_ERROR_OK)
				operation->padded = true;
		}
	}
	operation->first = false;
out:
	return res;
}

/*
 * Initialize the `TEE_OperationHandle` for the given algorithm, mode,
 * objecttype, objectusage, attributeid, key and iv.  If returns
 * KM_ERROR_OK, the operation will be properly initialized (and should be
 * freed with TEE_FreeOperation).
 */
keymaster_error_t TA_aes_init_operation(uint32_t algorithm, uint32_t mode,
				uint32_t objecttype, uint32_t objectusage,
				uint32_t attributeid,
				void *keybuffer, uint32_t maxkeylen,
				void *iv, size_t ivlen,
				TEE_OperationHandle *op)
{
	TEE_Result result;
	keymaster_error_t res = KM_ERROR_INVALID_ARGUMENT;
	TEE_ObjectHandle trans_key;
	TEE_Attribute attrs;

	if (!keybuffer || !op)
		goto out;

	result = TEE_AllocateOperation(op,
				    algorithm,
				    mode,
				    (maxkeylen * 8));
	if (result != TEE_SUCCESS) {
		EMSG("can not allocate operation (0x%x)", result);
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}

	result = TEE_AllocateTransientObject(objecttype,
					  (maxkeylen * 8),
					  &trans_key);
	if (result != TEE_SUCCESS) {
		EMSG("can not allocate transient object 0x%x", result);
		res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out1;
	}
	TEE_RestrictObjectUsage(trans_key, objectusage);

	TEE_InitRefAttribute(&attrs,
			     attributeid,
			     keybuffer,
			     maxkeylen);
	result = TEE_PopulateTransientObject(trans_key, &attrs, 1);
	if (result != TEE_SUCCESS) {
		EMSG("populate transient object error");
		res = KM_ERROR_INVALID_ARGUMENT;
		goto out2;
	}
	result = TEE_SetOperationKey(*op, trans_key);
	if (result != TEE_SUCCESS) {
		EMSG("can not set operation key");
		res = KM_ERROR_INVALID_ARGUMENT;
		goto out2;
	}

	TEE_FreeTransientObject(trans_key);

	TEE_CipherInit(*op, iv, ivlen);

	return KM_ERROR_OK;

out2:
	TEE_FreeTransientObject(trans_key);
out1:
	TEE_FreeOperation(*op);
out:
	return res;
}
