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

#ifndef ANDROID_OPTEE_AUTH_H
#define ANDROID_OPTEE_AUTH_H

#define MAX_SUID 10

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "tables.h"

TEE_Result TA_InitializeAuthTokenKey(void);

keymaster_error_t TA_GetAuthTokenKey(TEE_Param params[TEE_NUM_PARAMS]);

keymaster_error_t TA_check_auth_token(const uint64_t *suid,
					const uint32_t suid_count,
					const hw_authenticator_type_t auth_type,
					const hw_auth_token_t *auth_token);

keymaster_error_t TA_do_auth(const keymaster_key_param_set_t in_params,
				const keymaster_key_param_set_t key_params);

#define HMAC_SHA256_KEY_SIZE_BYTE 32
#define HMAC_SHA256_KEY_SIZE_BIT (8*HMAC_SHA256_KEY_SIZE_BYTE)
#define HW_AUTH_TOKEN_VERSION 0

#endif/*ANDROID_OPTEE_AUTH_H*/
