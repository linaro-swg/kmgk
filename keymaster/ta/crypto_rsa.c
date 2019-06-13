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

#include "crypto_rsa.h"

static bool TA_is_signature_purpose(const keymaster_purpose_t purpose)
{
	return purpose == KM_PURPOSE_VERIFY || purpose == KM_PURPOSE_SIGN;
}

static uint32_t TA_get_hash_size(const TEE_OperationHandle *digest_op)
{
	TEE_OperationInfo operationInfo;

	TEE_GetOperationInfo(*digest_op, &operationInfo);
	switch (operationInfo.algorithm) {
		case TEE_ALG_MD5:
			return TEE_MD5_HASH_SIZE;
		case TEE_ALG_SHA1:
			return TEE_SHA1_HASH_SIZE;
		case TEE_ALG_SHA224:
			return TEE_SHA224_HASH_SIZE;
		case TEE_ALG_SHA256:
			return TEE_SHA256_HASH_SIZE;
		case TEE_ALG_SHA384:
			return TEE_SHA384_HASH_SIZE;
		case TEE_ALG_SHA512:
			return TEE_SHA512_HASH_SIZE;
		default:
			return 0;
	}
}

static keymaster_error_t TA_check_input_rsa(const keymaster_operation_t *operation,
				const uint8_t *in_buf, const uint32_t in_buf_l,
				const uint32_t key_size,
				const TEE_ObjectHandle obj_h)
{
	keymaster_error_t res = KM_ERROR_OK;
	uint8_t *modulus = NULL;
	uint32_t modulus_size = KM_RSA_ATTR_SIZE;
	uint32_t modulus_len = (key_size + 7) / 8;
	uint32_t hash_len = 0;
	uint32_t salt_len = 0;

	if (operation->purpose == KM_PURPOSE_SIGN &&
				operation->digest_op != NULL &&
				operation->padding == KM_PAD_RSA_PSS) {
		hash_len = TA_get_hash_size(operation->digest_op);
		/* salt should has same size as hash */
		salt_len = hash_len;
		/* 2 - is a number of additional bytes 0x01 and 0xbc */
		if (modulus_len < hash_len + salt_len + 2) {
			res = KM_ERROR_INVALID_ARGUMENT;
			EMSG("Too big hash for such RSA key");
		}
		return res;
	}
	if (operation->padding != KM_PAD_NONE)
		return res;
	/* For unpadded
	 * signing and encryption operations
	 */
	if (operation->purpose == KM_PURPOSE_SIGN ||
		  operation->purpose == KM_PURPOSE_ENCRYPT) {
		if (in_buf_l == key_size / 8) {
			/* If the data is the same length as the key */
			if (!modulus) {
				modulus = TEE_Malloc(modulus_size,
						TEE_MALLOC_FILL_ZERO);
				if (!modulus) {
					EMSG("Failed to allocate memory for RSA modulus");
					res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
					goto out;
				}
			}
			res = TEE_GetObjectBufferAttribute(obj_h,
						TEE_ATTR_RSA_MODULUS,
						modulus,
						&modulus_size);
			if (res != KM_ERROR_OK) {
				EMSG("Failed to read RSA key, res=%x", res);
				goto out;
			}
			if (TEE_MemCompare(in_buf, modulus, in_buf_l) >= 0) {
				/* but numerically larger */
				res = KM_ERROR_INVALID_ARGUMENT;
				EMSG("For RSA Sign and Encrypt with KM_PAD_NONE input data value must be not bigger then key");
				goto out;
			}
		}
	} else {/* For verification and decryption operations */
		if (in_buf_l != key_size / 8) {
			/* the data must be exactly
			 * as long as the key
			 */
			res = KM_ERROR_INVALID_INPUT_LENGTH;
			EMSG("For RSA Verify and Decrypt with KM_PAD_NONE input data langth must be equal to key length");
			goto out;
		}
	}
out:
	if (modulus)
		TEE_Free(modulus);
	return res;
}

keymaster_error_t TA_rsa_finish(keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output, uint32_t *out_size,
				const uint32_t key_size,
				const keymaster_blob_t signature,
				const TEE_ObjectHandle obj_h,
				bool *is_input_ext)
{
	keymaster_error_t res = KM_ERROR_OK;
	TEE_Attribute *attrs = NULL;
	uint32_t attrs_count = 0;
	uint32_t digest_out_size = KM_MAX_DIGEST_SIZE;
	uint8_t digest_out[KM_MAX_DIGEST_SIZE];
	uint8_t *in_buf = NULL;
	uint32_t in_buf_l = 0;

	if (*operation->digest_op != TEE_HANDLE_NULL) {
		res = TEE_DigestDoFinal(*operation->digest_op, input->data,
			input->data_length, digest_out, &digest_out_size);
		if (res != KM_ERROR_OK) {
			EMSG("Failed to obtain digest for RSA, res=%x", res);
			goto out;
		}
		in_buf = digest_out;
		in_buf_l = digest_out_size;
	} else {
		res = TA_append_sf_data(input, operation, is_input_ext);
		if (res != KM_ERROR_OK)
			goto out;
		/* No need to change output size when stored data is appended */
		in_buf = input->data;
		in_buf_l = input->data_length;
	}
	if (operation->purpose == KM_PURPOSE_VERIFY && (signature.data == NULL
					|| signature.data_length == 0)) {
		EMSG("RSA verification signature is absent");
		res = KM_ERROR_VERIFICATION_FAILED;
		goto out;
	}
	if (in_buf_l == 0 && (operation->padding != KM_PAD_NONE ||
			operation->got_input)
			&& !TA_is_signature_purpose(operation->purpose)) {
		*out_size = 0;
		goto out;
	}
	if (operation->padding == KM_PAD_NONE) {
		/* For unpadded
		 * signing and encryption operations
		 */
		if (operation->purpose == KM_PURPOSE_SIGN ||
			  operation->purpose == KM_PURPOSE_ENCRYPT ||
			  operation->purpose == KM_PURPOSE_DECRYPT) {
			/* if the provided data is shorter than the key */
			if (in_buf_l < key_size / 8) {
				/* the data must be zero-padded on
				 * the left before signing/encryption
				 */
				res = TA_do_rsa_pad(&in_buf, &in_buf_l,
								key_size);
				input->data = in_buf; /*Will be freed in TA_finish*/
				if (res != KM_ERROR_OK)
					goto out;
			}
			/* if the provided data is longer than the key */
			else if (in_buf_l > key_size / 8) {
				EMSG("RSA encryption of too-long message");
				res = KM_ERROR_INVALID_INPUT_LENGTH;
				goto out;
			}
		} else if (operation->purpose == KM_PURPOSE_VERIFY ) {
			/* Input is signature */
			in_buf = signature.data;
			in_buf_l = signature.data_length;
		}
	}
	res = TA_check_input_rsa(operation, in_buf, in_buf_l, key_size, obj_h);
	if (res != KM_ERROR_OK)
		goto out;
	switch (operation->purpose) {
	case KM_PURPOSE_ENCRYPT:
		if (operation->padding == KM_PAD_RSA_PKCS1_1_5_ENCRYPT) {
			/* Size of the RSA key must be at least
			 * 11 bytes larger than the message
			 */
			if (in_buf_l + 11 > key_size / 8) {
				EMSG("RSA key must be at least 11 bytes larger than the message");
				res = KM_ERROR_INVALID_INPUT_LENGTH;
				goto out;
			}
		}
		if (operation->padding == KM_PAD_RSA_OAEP) {
			/* mLen <= k - 2hLen - 2 */
			if (in_buf_l + 2 + 2 * operation->digestLength > key_size / 8) {
				EMSG("RSA OAEP encryption too large message %d", in_buf_l);
				res = KM_ERROR_INVALID_INPUT_LENGTH;
				goto out;
			}
		}
		res = TEE_AsymmetricEncrypt(*operation->operation, NULL, 0,
					in_buf, in_buf_l,
					output->data, out_size);
		break;
	case KM_PURPOSE_DECRYPT:
		res = TEE_AsymmetricDecrypt(*operation->operation, NULL, 0,
					in_buf, in_buf_l,
					output->data, out_size);
		break;
	case KM_PURPOSE_VERIFY:
	case KM_PURPOSE_SIGN:
		if (operation->padding == KM_PAD_RSA_PKCS1_1_5_SIGN) {
			/* Size of the RSA key must be at least
			 * 11 bytes larger than the message
			 */
			if (in_buf_l + 11 > key_size / 8) {
				EMSG("RSA key must be at least 11 bytes larger than the message");
				res = KM_ERROR_INVALID_INPUT_LENGTH;
				goto out;
			}

			if (*operation->digest_op == TEE_HANDLE_NULL) {
				res = TA_do_rsa_pkcs_v1_5_rawpad(&in_buf,
								 &in_buf_l,
								 key_size);
				input->data = in_buf;
				input->data_length = in_buf_l;
				if (res != KM_ERROR_OK)
					goto out;

				if (operation->purpose == KM_PURPOSE_VERIFY) {
					in_buf = signature.data;
					in_buf_l = signature.data_length;
					res = TEE_AsymmetricEncrypt(*operation->operation,
								    NULL, 0,
								    in_buf,
								    in_buf_l, /*in: signature*/
								    output->data,
								    out_size); /*out: message + padding*/
					if ((uint32_t)res == TEE_ERROR_BAD_PARAMETERS ||
					    (uint32_t)res == TEE_ERROR_SHORT_BUFFER) {
						res = KM_ERROR_UNKNOWN_ERROR;
						goto out;
					}

					output->data_length = *out_size;
					*out_size = 0;
					/* input->data starts from zero-byte */
					if (TEE_MemCompare(output->data,
							   input->data + 1,
							   output->data_length) != 0) {
						EMSG("RSA no pad verification signature failed");
						res = KM_ERROR_VERIFICATION_FAILED;
						goto out;
					}
				} else if (operation->purpose == KM_PURPOSE_SIGN) {
					res = TEE_AsymmetricDecrypt(*operation->operation,
								    NULL, 0,
								    in_buf,
								    in_buf_l,
								    output->data,
								    out_size);
				}
				break;
			}
		}
		if (operation->purpose == KM_PURPOSE_VERIFY &&
				operation->padding != KM_PAD_NONE) {
			*out_size = 0;
			res = TEE_AsymmetricVerifyDigest(*operation->operation,
						attrs, attrs_count, in_buf,
						in_buf_l,
						signature.data,
						signature.data_length);
			/* Convert error code to Android style */
			if ((uint32_t) res == TEE_ERROR_SIGNATURE_INVALID)
				res = KM_ERROR_VERIFICATION_FAILED;
		} else if (operation->purpose == KM_PURPOSE_SIGN &&
				operation->padding != KM_PAD_NONE) {
			res = TEE_AsymmetricSignDigest(*operation->operation,
						attrs,
						attrs_count,
						in_buf,
						in_buf_l,
						output->data,
						out_size);
			/* Convert error code to Android style */
			if (res == (int) TEE_ERROR_SHORT_BUFFER &&
					operation->padding ==
					KM_PAD_RSA_PKCS1_1_5_SIGN) {
				res = KM_ERROR_INVALID_ARGUMENT;
			}
		} else if (operation->purpose == KM_PURPOSE_VERIFY &&
				operation->padding == KM_PAD_NONE) {
			res = TEE_AsymmetricEncrypt(*operation->operation, NULL, 0,
						in_buf, in_buf_l, /*in: signature*/
						output->data, out_size); /*out: message + padding*/
			if ((uint32_t)res == TEE_ERROR_BAD_PARAMETERS ||
					(uint32_t)res == TEE_ERROR_SHORT_BUFFER)
				res = KM_ERROR_UNKNOWN_ERROR;

			output->data_length = *out_size;
			*out_size = 0;
			if (TEE_MemCompare(output->data, input->data,
					output->data_length) != 0) {
				EMSG("RSA no pad verification signature failed");
				res = KM_ERROR_VERIFICATION_FAILED;
				goto out;
			}
		} else if (operation->purpose == KM_PURPOSE_SIGN &&
				operation->padding == KM_PAD_NONE) {
			res = TEE_AsymmetricDecrypt(*operation->operation, NULL, 0,
						in_buf, in_buf_l,
						output->data, out_size);
		}
		break;
	default:
		res = KM_ERROR_UNSUPPORTED_PURPOSE;
		goto out;
	}
	if (res == KM_ERROR_OK && *out_size < key_size / 8
				&& operation->padding == KM_PAD_NONE &&
				(operation->purpose == KM_PURPOSE_ENCRYPT ||
				operation->purpose == KM_PURPOSE_DECRYPT)) {
		/*
		 * If result is left padded with zeroes TEE_AsymmetricEncrypt
		 * and TEE_AsymmetricEncrypt for unpadded operation truncate all
		 * zeroes but one if it is the last. Restore result array.
		 */
		res = TA_do_rsa_pad(&output->data, out_size, key_size);
	}
	/* Convert error code to Android type */
	if (res == (int) TEE_ERROR_BAD_PARAMETERS &&
				operation->padding != KM_PAD_NONE)
		res = KM_ERROR_UNKNOWN_ERROR;
out:
	return res;
}

keymaster_error_t TA_rsa_update(keymaster_operation_t *operation,
				const keymaster_blob_t *input,
				keymaster_blob_t *output,
				uint32_t *out_size,
				const uint32_t key_size,
				size_t *input_consumed,
				const uint32_t input_provided,
				const TEE_ObjectHandle obj_h)
{
	keymaster_error_t res = KM_ERROR_OK;
	uint32_t key_bytes = (key_size + 7) / 8;

	if (input->data_length > key_bytes &&
			*operation->digest_op == TEE_HANDLE_NULL) {
		EMSG("Input (%lu) exeeds RSA key size (%u)",
					input->data_length, key_bytes);
		return KM_ERROR_INVALID_INPUT_LENGTH;
	}
	switch (operation->purpose) {
	case KM_PURPOSE_ENCRYPT:
	case KM_PURPOSE_DECRYPT:
		if (operation->padding == KM_PAD_NONE) {
			res = TA_check_input_rsa(operation, input->data,
						input->data_length,
						key_size, obj_h);
			if (res == KM_ERROR_INVALID_INPUT_LENGTH) {
				res = TA_store_sf_data(input, operation);
				*input_consumed = input_provided;
				output->data_length = 0;
				break;
			} else 	if (res != KM_ERROR_OK)
				return res;
			if (operation->purpose == KM_PURPOSE_DECRYPT) {
				res = TEE_AsymmetricDecrypt(
						*operation->operation,
						NULL, 0, input->data,
						input->data_length,
						output->data, out_size);
			} else {
				res = TEE_AsymmetricEncrypt(
						*operation->operation,
						NULL, 0, input->data,
						input->data_length,
						output->data, out_size);
			}
			if (operation->padding == KM_PAD_NONE &&
				res == KM_ERROR_OK && *out_size < key_bytes)
				/*
				 * If result is left padded with
				 * zeroes TEE_AsymmetricDecrypt and
				 * TEE_AsymmetricDecrypt for unpadded
				 * operation truncate all zeroes but one
				 * if it is the last. Restore result.
				 */
				res = TA_do_rsa_pad(&output->data, out_size,
								key_size);
			/* Convert error code to Android type */
			if (res == (int) TEE_ERROR_BAD_PARAMETERS &&
				      operation->padding != KM_PAD_NONE)
				res = KM_ERROR_INVALID_INPUT_LENGTH;
			*input_consumed = input_provided;
			output->data_length = *out_size;
			break;
		}
		/* fall through */
		/* __attribute__((fallthrough)); */
		/* https://stackoverflow.com/questions/45349079/how-to-use-attribute-fallthrough-correctly-in-gcc */
		/*
		 * __attribute__ ((fallthrough)) was introduced in GCC 7. To
		 * maintain backward compatibility and clear the fall through
		 * warning for both Clang and GCC, you can use the "fall
		 * through" marker comment.
		 */
	case KM_PURPOSE_VERIFY:
	case KM_PURPOSE_SIGN:
		if (*operation->digest_op != TEE_HANDLE_NULL) {
			TEE_DigestUpdate(*operation->digest_op,
					input->data, input->data_length);
		} else {
			/* if digest is not specified save all
			 * blocks to use it in finish
			 */
			res = TA_store_sf_data(input, operation);
		}
		*input_consumed = input_provided;
		output->data_length = 0;
		break;
	default:
		res = KM_ERROR_UNSUPPORTED_PURPOSE;
	}
	return res;
}
