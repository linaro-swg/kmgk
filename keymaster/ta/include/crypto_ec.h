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

#ifndef ANDROID_OPTEE_CRYPTO_EC_H
#define ANDROID_OPTEE_CRYPTO_EC_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "shift.h"
#include "ta_ca_defs.h"
#include "operations.h"
#include "crypto_rsa.h"
#include "asn1.h"

keymaster_error_t TA_ec_update(keymaster_operation_t *operation,
				const keymaster_blob_t *input,
				keymaster_blob_t *output,
				size_t *input_consumed,
				const uint32_t input_provided);

keymaster_error_t TA_ec_finish(const keymaster_operation_t *operation,
				keymaster_blob_t *input,
				keymaster_blob_t *output,
				keymaster_blob_t *signature,
				uint32_t *out_size,
				const uint32_t key_size,
				bool *is_input_ext);

#endif/* ANDROID_OPTEE_CRYPTO_EC_H */
