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

#ifndef ANDROID_OPTEE_OPERATIONS_H
#define ANDROID_OPTEE_OPERATIONS_H

#define KM_MAX_OPERATION 20U

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "tables.h"
#include "master_crypto.h"

typedef struct keymaster_blob_list_item_t {
	keymaster_blob_t data;
	struct keymaster_blob_list_item_t *next;
} keymaster_blob_list_item_t;

typedef struct {
	uint8_t key_id[TAG_LENGTH];
	keymaster_key_blob_t *key;
	keymaster_blob_t nonce;
	keymaster_blob_t last_block;
	keymaster_operation_handle_t op_handle;
	keymaster_purpose_t purpose;
	keymaster_padding_t padding;
	keymaster_block_mode_t mode;
	keymaster_blob_list_item_t *sf_item;/*sign/verify data*/
	TEE_Time *last_access;
	TEE_OperationHandle *operation;
	TEE_OperationHandle *digest_op;
	size_t prev_in_size;
	uint32_t min_sec;
	uint32_t mac_length;
	uint32_t digestLength;
	uint32_t a_data_length;
	uint8_t *a_data;
	bool do_auth;
	bool got_input;
	bool buffering;
	bool padded;
	bool first;
} keymaster_operation_t;

void TA_free_blob_list(keymaster_blob_list_item_t *item);

keymaster_error_t TA_try_start_operation(
				const keymaster_operation_handle_t op_handle,
				const keymaster_key_blob_t key,
				const uint32_t min_sec,
				TEE_OperationHandle *operation,
				const keymaster_purpose_t purpose,
				TEE_OperationHandle *digest_op,
				const bool do_auth,
				const keymaster_padding_t padding,
				const keymaster_block_mode_t mode,
				const uint32_t mac_length,
				const keymaster_digest_t digest,
				const keymaster_blob_t nonce,
				uint8_t *key_id);

keymaster_error_t TA_start_operation(
				const keymaster_operation_handle_t op_handle,
				const keymaster_key_blob_t key,
				const uint32_t min_sec,
				TEE_OperationHandle *operation,
				const keymaster_purpose_t purpose,
				TEE_OperationHandle *digest_op,
				const bool do_auth,
				const keymaster_padding_t padding,
				const keymaster_block_mode_t mode,
				const uint32_t mac_length,
				const keymaster_digest_t digest,
				const keymaster_blob_t nonce,
				uint8_t *key_id);

keymaster_error_t TA_get_operation(const keymaster_operation_handle_t op_handle,
				keymaster_operation_t *operation);

keymaster_error_t TA_update_operation(const keymaster_operation_handle_t op_handle,
				keymaster_operation_t *operation);

keymaster_error_t TA_kill_old_operation(void);

keymaster_error_t TA_abort_operation(
	const keymaster_operation_handle_t op_handle);

keymaster_error_t TA_store_sf_data(const keymaster_blob_t *input,
				keymaster_operation_t *operation);

keymaster_error_t TA_append_sf_data(keymaster_blob_t *input,
				const keymaster_operation_t *operation,
				bool *is_input_ext);

void TA_add_to_nonce(keymaster_operation_t *operation, const uint64_t value);

void TA_decriment_nonce(keymaster_operation_t *operation);

void TA_reset_operations_table(void);

#endif  /* ANDROID_OPTEE_OPERATIONS_H */
