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

#ifndef ANDROID_OPTEE_CRYPTO_AES_H
#define ANDROID_OPTEE_CRYPTO_AES_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "operations.h"
#include "paddings.h"

keymaster_error_t TA_aes_finish(keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output, uint32_t *out_size,
				uint32_t tag_len, bool *is_input_ext,
				const keymaster_key_param_set_t *in_params);

keymaster_error_t TA_aes_update(keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output,
				uint32_t *out_size,
				const uint32_t input_provided,
				size_t *input_consumed,
				const keymaster_key_param_set_t *in_params,
				bool *is_input_ext);

keymaster_error_t TA_aes_init_operation(uint32_t algorithm, uint32_t mode,
				uint32_t objecttype, uint32_t objectusage,
				uint32_t attributeid,
				void *keybuffer, uint32_t maxkeylen,
				void *iv, size_t ivlen,
				TEE_OperationHandle *op);

#endif/*ANDROID_OPTEE_CRYPTO_AES_H*/
