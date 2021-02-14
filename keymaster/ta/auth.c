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

#include "auth.h"

/*
 * auth_token key persistent object id
 */
static uint8_t auth_token_key_id[] = { 0xB1, 0x60, 0x71, 0x75 };

/*
 * This function creates auth_token key persistent object if it doesn't exist.
 * This function should be called once in TA_CreateEntryPoint function.
 *
 * @return TEE_SUCCESS on success
 */
TEE_Result TA_InitializeAuthTokenKey(void)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle auth_token_key_obj = TEE_HANDLE_NULL;
	uint8_t auth_token_key[HMAC_SHA256_KEY_SIZE_BYTE] = { 0 };

	DMSG("Checking auth_token key secret");

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
			auth_token_key_id, sizeof(auth_token_key_id),
			TEE_DATA_FLAG_ACCESS_READ, &auth_token_key_obj);

	switch(res) {
	case TEE_ERROR_ITEM_NOT_FOUND:
		DMSG("Create auth_token key secret");

		TEE_GenerateRandom(auth_token_key, sizeof(auth_token_key));
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
				auth_token_key_id, sizeof(auth_token_key_id),
				TEE_DATA_FLAG_ACCESS_WRITE,
				TEE_HANDLE_NULL, NULL, 0, &auth_token_key_obj);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to create auth_token key secret, res=%x", res);
			goto out;
		}

		res = TEE_WriteObjectData(auth_token_key_obj,
				(void *)auth_token_key,
				sizeof(auth_token_key));

		/* erase auth_token_key from memory */
		TEE_MemFill(auth_token_key, 0, sizeof(auth_token_key));

		if (res != TEE_SUCCESS) {
			EMSG("Failed to write auth_token key secret, res=%x", res);
			goto close_obj;
		}

		break;
	case TEE_SUCCESS:
		DMSG("auth_token key secret is already created");
		break;
	default:
		EMSG("Failed to open auth_token key secret, res=%x", res);
		goto out;
	}

close_obj:
	TEE_CloseObject(auth_token_key_obj);
out:
	return res;
}

/*
 * This function fills @identity parameter with current client identity
 * value. @identity parameter should point to the valid TEE_Identity object
 *
 * @return TEE_SUCCESS on success
 */
static TEE_Result TA_GetClientIdentity(TEE_Identity *identity)
{
	TEE_Result res = TEE_SUCCESS;

	res = TEE_GetPropertyAsIdentity(TEE_PROPSET_CURRENT_CLIENT,
			(char *)"gpd.client.identity", identity);

	if (res != TEE_SUCCESS) {
		EMSG("Failed to get property, res=%x", res);
		goto exit;
	}

exit:
	return res;
}

/*
 * This function fills @key array with secret value for auth_token key.
 * @key_size parameter is the @key array size. @key parameter should
 * point to the valid memory that has size at least @key_size
 *
 * @return TEE_SUCCESS on success
 */
static TEE_Result TA_ReadAuthTokenKey(uint8_t *key, uint32_t key_size)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle auth_token_key_obj = TEE_HANDLE_NULL;
	uint32_t read_size = 0;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
			auth_token_key_id, sizeof(auth_token_key_id),
			TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ,
			&auth_token_key_obj);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open auth_token key secret, res=%x", res);
		goto exit;
	}

	res = TEE_ReadObjectData(auth_token_key_obj, key,
			key_size, &read_size);
	if (res != TEE_SUCCESS || key_size != read_size) {
		EMSG("Failed to read secret data, bytes = %u, res=%x", read_size, res);
		goto close_obj;
	}

close_obj:
	TEE_CloseObject(auth_token_key_obj);
exit:
	return res;
}

keymaster_error_t TA_GetAuthTokenKey(TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Identity identity;
	uint8_t auth_token_key[HMAC_SHA256_KEY_SIZE_BYTE];

	res = TA_GetClientIdentity(&identity);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get identity property, res=%x", res);
		goto exit;
	}

	if (identity.login != TEE_LOGIN_TRUSTED_APP) {
		EMSG("Not trusted app trying to get auth_token key");
		res = TEE_ERROR_ACCESS_DENIED;
		goto exit;
	}

	DMSG("%pUl requests auth_token key", (void *)&identity.uuid);
	res = TA_ReadAuthTokenKey(auth_token_key, sizeof(auth_token_key));
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get auth_token key, res=%x", res);
		goto exit;
	}

	if (params[1].memref.size < sizeof(auth_token_key)) {
		EMSG("Output buffer to small");
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}

	TEE_MemMove(params[1].memref.buffer, auth_token_key,
			sizeof(auth_token_key));

exit:
	return res;
}

/*
 * This function checks that @in_params and @key_params meet all necessary
 * requirements. After that, it checks hw_auth_token signature.
 */
keymaster_error_t TA_do_auth(const keymaster_key_param_set_t in_params,
				const keymaster_key_param_set_t key_params)
{
	uint64_t suid[MAX_SUID];
	uint32_t suid_count = 0;
	bool found_token = false;
	hw_authenticator_type_t auth_type = UNDEFINED;
	hw_auth_token_t auth_token;
	keymaster_error_t res = KM_ERROR_OK;

	for (size_t i = 0; i < key_params.length; i++) {
		switch (key_params.params[i].tag) {
		case KM_TAG_NO_AUTH_REQUIRED:
		case KM_TAG_AUTH_TIMEOUT:
			/*
			 * If no auth is required or if auth is timeout-based,
			 * we have nothing to check.
			 */
			res = KM_ERROR_OK;
			goto exit;
		case KM_TAG_USER_SECURE_ID:
			if (suid_count + 1 > MAX_SUID) {
				EMSG("To many SUID. Expected max count %u",
								MAX_SUID);
				break;
			}
			suid[suid_count] = key_params.params[i].
						key_param.long_integer;
			suid_count++;
			break;
		case KM_TAG_USER_AUTH_TYPE:
			auth_type = (hw_authenticator_type_t)
				key_params.params[i].key_param.enumerated;
			break;
		default:
			break;
		}
	}

	for (size_t i = 0; i < in_params.length; i++) {
		if (in_params.params[i].tag == KM_TAG_AUTH_TOKEN) {
			if (in_params.params[i].key_param.blob.data_length ==
					sizeof(auth_token)) {
				found_token = true;
				TEE_MemMove(&auth_token,
					in_params.params[i].key_param.blob.data,
					sizeof(auth_token));
			}
		}
	}

	if (!suid_count || !found_token) {
		EMSG("Authentication failed. Key can not be used");
		res = KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
		goto exit;
	}

	res = TA_check_auth_token(suid, suid_count, auth_type, &auth_token);

exit:
	return res;
}

/*
 * Compute HMAC for @message buffer that has @length byte size. Operation key
 * is @key. The output will be stored in @signature and will be truncated if it
 * will be greater than @signature_length.
 * All parameters have to be valid.
 *
 * @return TEE_SUCCESS on success
 */
static TEE_Result TA_ComputeSignature(uint8_t *signature, size_t signature_length,
	TEE_ObjectHandle key, const uint8_t *message, size_t length)
{
	uint32_t		buf_length = HMAC_SHA256_KEY_SIZE_BYTE;
	uint8_t			buf[buf_length];
	TEE_OperationHandle	op = TEE_HANDLE_NULL;
	TEE_Result		res;
	uint32_t		to_write;

	res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC,
			HMAC_SHA256_KEY_SIZE_BIT);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate HMAC operation, res=%x", res);
		goto exit;
	}

	res = TEE_SetOperationKey(op, key);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to set secret key, res=%x", res);
		goto free_op;
	}

	TEE_MACInit(op, NULL, 0);

	res = TEE_MACComputeFinal(op, (void *)message, length, buf, &buf_length);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to compute HMAC, res=%x", res);
		goto free_op;
	}

	to_write = buf_length;
	if (buf_length > signature_length)
		to_write = signature_length;

	memset(signature, 0, signature_length);
	memcpy(signature, buf, to_write);

free_op:
	TEE_FreeOperation(op);
exit:
	return res;
}

/*
 * This function sets to @auth_token_key_obj parameter handler to
 * auth_token key. @auth_token_key_obj parameter should be initialized
 * with TEE_AllocateTransientObject function (type - TEE_TYPE_HMAC_SHA256,
 * size - HMAC_SHA256_KEY_SIZE_BIT).
 *
 * @return TEE_SUCCESS on success
 */
static TEE_Result TA_GetAuthKeyObj(TEE_ObjectHandle auth_token_key_obj)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Attribute attrs[1];
	uint8_t auth_token_key[HMAC_SHA256_KEY_SIZE_BYTE];

	res = TA_ReadAuthTokenKey(auth_token_key, sizeof(auth_token_key));
	if (res != TEE_SUCCESS) {
		EMSG("Failed to create auth_token key object, res=%x", res);
		goto exit;
	}

	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_SECRET_VALUE, auth_token_key,
			sizeof(auth_token_key));

	res = TEE_PopulateTransientObject(auth_token_key_obj, attrs,
			sizeof(attrs)/sizeof(attrs[0]));
	if (res != TEE_SUCCESS) {
		EMSG("Failed to set auth_token key attributes, res=%x", res);
		goto exit;
	}

exit:
	return res;
}

/*
 * Check that authintication token @token has valid HMAC value.
 *
 * @return TEE_SUCCESS on success
 */
static TEE_Result TA_ValidateTokenSignature(const hw_auth_token_t *token)
{
	TEE_Result res = TEE_SUCCESS;

	// Signature covers entire token except HMAC field.
	const uint8_t *token_data = (const uint8_t *)token;
	const uint32_t token_data_length = (const uint8_t *)token->hmac - token_data;

	const uint32_t computed_hmac_length = sizeof(token->hmac);
	uint8_t computed_hmac[computed_hmac_length];

	TEE_ObjectHandle auth_token_key_obj = TEE_HANDLE_NULL;

	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256,
			HMAC_SHA256_KEY_SIZE_BIT, &auth_token_key_obj);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate auth_token_key_obj, res=%x", res);
		goto exit;
	}

	res = TA_GetAuthKeyObj(auth_token_key_obj);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get auth_token key object, res=%x", res);
		goto close_obj;
	}

	res = TA_ComputeSignature(computed_hmac, computed_hmac_length, auth_token_key_obj,
			token_data, token_data_length);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to compute auth_token signature, res=%x", res);
		goto close_obj;
	}

	if (memcmp(token->hmac, computed_hmac, computed_hmac_length) != 0) {
		res = TEE_ERROR_MAC_INVALID;
		EMSG("auth_token has invallid HMAC");
		goto close_obj;
	}

close_obj:
	TEE_CloseObject(auth_token_key_obj);
exit:
	return res;
}

/*
 * This function validate @auth_token parameter.
 *
 * @return TEE_SUCCESS on success or KM_ERROR_KEY_USER_NOT_AUTHENTICATED
 * if any of requirements are not met
*/
keymaster_error_t TA_check_auth_token(const uint64_t *suid,
					const uint32_t suid_count,
					const hw_authenticator_type_t auth_type,
					const hw_auth_token_t *auth_token)
{
	TEE_Result	res;
	bool		in_list = false;

	/*
	 * At least one of the KM_TAG_USER_SECURE_ID values from the key must
	 * match the secure ID value in the auth_token
	 */
	for (uint32_t i = 0; i < suid_count; i++) {
		if (auth_token->user_id == suid[i]) {
			in_list = true;
			break;
		}
	}
	if (!in_list) {
		EMSG("Suid from auth token not in list of this key");
		return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
	}
	if ((TEE_U32_FROM_BIG_ENDIAN(auth_token->authenticator_type) &
						(uint32_t) auth_type) == 0) {
		EMSG("Authentication type not passed");
		return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
	}

	if (auth_token->version != HW_AUTH_TOKEN_VERSION) {
		EMSG("auth_token has %u version, expected %u",
				auth_token->version, HW_AUTH_TOKEN_VERSION);
		return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
	}

	res = TA_ValidateTokenSignature(auth_token);
	switch (res) {
	case TEE_SUCCESS:
		break;
	case TEE_ERROR_MAC_INVALID:
		EMSG("auth_token failed validation");
		return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
	default:
		EMSG("Validation failed");
		return KM_ERROR_UNKNOWN_ERROR;
	}

	return res;
}
