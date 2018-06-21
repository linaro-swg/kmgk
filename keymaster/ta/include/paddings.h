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

#ifndef ANDROID_OPTEE_PADDINGS_H
#define ANDROID_OPTEE_PADDINGS_H

#define BLOCK_SIZE 16U

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"

keymaster_error_t TA_check_out_size(const uint32_t input_l,
					keymaster_blob_t *output,
					uint32_t *out_size,
					uint32_t tag_len);

keymaster_error_t TA_add_pkcs7_pad(keymaster_blob_t *input,
				const bool force, keymaster_blob_t *output,
				uint32_t *out_size, bool *is_input_ext);

keymaster_error_t TA_remove_pkcs7_pad(keymaster_blob_t *output,
					uint32_t *out_size);

bool TA_check_pkcs7_pad(keymaster_blob_t *output);

keymaster_error_t TA_do_rsa_pad(uint8_t **input, uint32_t *input_l,
				const uint32_t key_size);

keymaster_error_t TA_do_rsa_pkcs_v1_5_rawpad(uint8_t **input, uint32_t *input_l,
					     const uint32_t key_size);

#endif/* ANDROID_OPTEE_PADDINGS_H */
