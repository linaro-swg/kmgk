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

#include "operations.h"
#include "parameters.h"

static keymaster_operation_t operations[KM_MAX_OPERATION];

void TA_free_blob_list(keymaster_blob_list_item_t *item)
{
	keymaster_blob_list_item_t *prev;

	while (item != NULL) {
		if (item->data.data)
			TEE_Free(item->data.data);
		prev = item;
		item = item->next;
		TEE_Free(prev);
	}
}

keymaster_error_t TA_abort_operation(
	const keymaster_operation_handle_t op_handle)
{
	keymaster_error_t res = KM_ERROR_INVALID_OPERATION_HANDLE;

	for (uint32_t i = 0; i < KM_MAX_OPERATION; i++) {
		if (op_handle == operations[i].op_handle) {
			res = KM_ERROR_OK;
			if (operations[i].min_sec != UNDEFINED) {
				TA_trigger_timer(operations[i].key_id);
			}
			operations[i].op_handle = UNDEFINED;
			if (operations[i].key != NULL) {
				if (operations[i].key->key_material)
					TEE_Free(operations[i].key->
							key_material);
				TEE_Free(operations[i].key);
			}
			operations[i].key = NULL;
			operations[i].last_access = NULL;
			operations[i].min_sec = UNDEFINED;
			if (*operations[i].operation != TEE_HANDLE_NULL)
				TEE_FreeOperation(*operations[i].operation);
			TEE_Free(operations[i].operation);
			operations[i].operation = TEE_HANDLE_NULL;
			operations[i].purpose = UNDEFINED;
			operations[i].do_auth = false;
			if (*operations[i].digest_op != TEE_HANDLE_NULL)
				TEE_FreeOperation(*operations[i].digest_op);
			TEE_Free(operations[i].digest_op);
			operations[i].padding = UNDEFINED;
			operations[i].mode = UNDEFINED;
			operations[i].got_input = false;
			if (operations[i].sf_item)
				TA_free_blob_list(operations[i].sf_item);
			operations[i].sf_item = NULL;
			operations[i].mac_length = UNDEFINED;
			operations[i].digestLength = UNDEFINED;
			if (operations[i].a_data)
				TEE_Free(operations[i].a_data);
			operations[i].a_data = NULL;
			operations[i].a_data_length = 0;
			operations[i].buffering = false;
			operations[i].prev_in_size = UNDEFINED;
			if (operations[i].nonce.data)
				TEE_Free(operations[i].nonce.data);
			operations[i].nonce.data = NULL;
			operations[i].nonce.data_length = 0;
			operations[i].padded = false;
			operations[i].first = true;
			if (operations[i].last_block.data)
				TEE_Free(operations[i].last_block.data);
			operations[i].last_block.data = NULL;
			operations[i].last_block.data_length = 0;
			TEE_MemFill(operations[i].key_id, 0,
				    sizeof(operations[i].key_id));
			break;
		}
	}
	return res;
}

void TA_reset_operations_table(void)
{
	for (uint32_t i = 0; i < KM_MAX_OPERATION; i++) {
		operations[i].op_handle = UNDEFINED;
		operations[i].key = NULL;
		operations[i].last_access = NULL;
		operations[i].min_sec = UNDEFINED;
		operations[i].operation = TEE_HANDLE_NULL;
		operations[i].purpose = UNDEFINED;
		operations[i].do_auth = false;
		operations[i].digest_op = TEE_HANDLE_NULL;
		operations[i].padding = UNDEFINED;
		operations[i].mode = UNDEFINED;
		operations[i].got_input = false;
		operations[i].sf_item = NULL;
		operations[i].mac_length = UNDEFINED;
		operations[i].digestLength = UNDEFINED;
		operations[i].a_data = NULL;
		operations[i].a_data_length = 0;
		operations[i].buffering = false;
		operations[i].prev_in_size = UNDEFINED;
		operations[i].nonce.data = NULL;
		operations[i].nonce.data_length = 0;
		operations[i].last_block.data = NULL;
		operations[i].last_block.data_length = 0;
		operations[i].first = true;
		operations[i].padded = false;
		TEE_MemFill(operations[i].key_id, 0,
			    sizeof(operations[i].key_id));
	}
}

keymaster_error_t TA_kill_old_operation(void)
{
	keymaster_operation_t oldest;

	oldest = operations[0];
	for (uint32_t i = 1; i < KM_MAX_OPERATION; i++) {
		if (oldest.last_access->seconds >
				operations[i].last_access->seconds ||
				(oldest.last_access->seconds ==
				operations[i].last_access->seconds &&
				oldest.last_access->millis >
				operations[i].last_access->millis)) {
			oldest = operations[i];
		}
	}
	return TA_abort_operation(oldest.op_handle);
}

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
				uint8_t *key_id)
{
	TEE_Time cur_t;

	for (uint32_t i = 0; i < KM_MAX_OPERATION; i++) {
		if (operations[i].op_handle == UNDEFINED) {
			TEE_GetSystemTime(&cur_t);
			/* freed when operation aborted (TA_abort_operation) */
			operations[i].key = TEE_Malloc(
					sizeof(keymaster_key_blob_t),
					TEE_MALLOC_FILL_ZERO);
			if (!operations[i].key) {
				EMSG("Failed to allocate memory for operation key struct");
				return KM_ERROR_MEMORY_ALLOCATION_FAILED;
			}
			operations[i].key->key_material_size =
							key.key_material_size;
			/* freed when operation aborted (TA_abort_operation) */
			operations[i].key->key_material = TEE_Malloc(
						key.key_material_size,
						TEE_MALLOC_FILL_ZERO);
			if (!operations[i].key->key_material) {
				EMSG("Failed to allocate memory for operation key data");
				TEE_Free(operations[i].key);
				return KM_ERROR_MEMORY_ALLOCATION_FAILED;
			}
			TEE_MemMove(operations[i].key->key_material,
						key.key_material,
						key.key_material_size);
			operations[i].last_access = &cur_t;
			operations[i].min_sec = min_sec;
			operations[i].operation = operation;
			operations[i].purpose = purpose;
			operations[i].do_auth = do_auth;
			operations[i].digest_op = digest_op;
			operations[i].mac_length = mac_length;
			operations[i].padding = padding;
			operations[i].mode = mode;
			operations[i].digestLength = get_digest_size(&digest) / 8; /*in bytes*/
			operations[i].nonce.data = TEE_Malloc(
						nonce.data_length,
						TEE_MALLOC_FILL_ZERO);
			if (!operations[i].nonce.data) {
				EMSG("Failed to allocate memory for nonce");
				TEE_Free(operations[i].key->key_material);
				TEE_Free(operations[i].key);
				return KM_ERROR_MEMORY_ALLOCATION_FAILED;
			}
			TEE_MemMove(operations[i].nonce.data,
					nonce.data, nonce.data_length);
			operations[i].nonce.data_length = nonce.data_length;
			operations[i].op_handle = op_handle;
			memcpy(operations[i].key_id, key_id,
					sizeof(operations[i].key_id));
			return KM_ERROR_OK;
		}
	}
	return KM_ERROR_TOO_MANY_OPERATIONS;
}

keymaster_error_t TA_start_operation(
				const keymaster_operation_handle_t op_handle,
				const keymaster_key_blob_t key, uint32_t min_sec,
				TEE_OperationHandle *operation,
				const keymaster_purpose_t purpose,
				TEE_OperationHandle *digest_op,
				const bool do_auth,
				const keymaster_padding_t padding,
				const keymaster_block_mode_t mode,
				const uint32_t mac_length,
				const keymaster_digest_t digest,
				const keymaster_blob_t nonce,
				uint8_t *key_id)
{
	keymaster_error_t res = TA_try_start_operation(op_handle, key, min_sec,
						       operation, purpose,
						       digest_op, do_auth,
						       padding, mode,
						       mac_length, digest,
						       nonce, key_id);
	if (res != KM_ERROR_OK) {
		res = TA_kill_old_operation();
		if (res == KM_ERROR_OK) {
			res = TA_try_start_operation(op_handle, key, min_sec,
						     operation, purpose,
						     digest_op, do_auth,
						     padding, mode,
						     mac_length, digest,
						     nonce, key_id);
		}
	}
	return res;
}

keymaster_error_t TA_get_operation(const keymaster_operation_handle_t op_handle,
					keymaster_operation_t *operation)
{
	keymaster_error_t res = KM_ERROR_INVALID_OPERATION_HANDLE;
	TEE_Time cur_t;

	for (uint32_t i = 0; i < KM_MAX_OPERATION; i++) {
		if (op_handle == operations[i].op_handle) {
			TEE_GetSystemTime(&cur_t);
			operations[i].last_access = &cur_t;
			res = KM_ERROR_OK;
			*operation = operations[i];
			break;
		}
	}
	return res;
}

keymaster_error_t TA_update_operation(keymaster_operation_handle_t op_handle,
					keymaster_operation_t *operation)
{
	keymaster_error_t res = KM_ERROR_INVALID_OPERATION_HANDLE;

	for (uint32_t i = 0; i < KM_MAX_OPERATION; i++) {
		if (op_handle == operations[i].op_handle) {
			operations[i] = *operation;
			break;
		}
	}
	return res;
}

keymaster_error_t TA_store_sf_data(const keymaster_blob_t *input,
					keymaster_operation_t *operation)
{
	keymaster_blob_list_item_t *new;
	keymaster_blob_list_item_t *current = operation->sf_item;
	/* freed when operation is aborted (TA_abort_operation) */
	new = TEE_Malloc(sizeof(keymaster_blob_list_item_t),
					TEE_MALLOC_FILL_ZERO);
	if (!new) {
		EMSG("Failed to allocate memory for buffered sign/veify data struct");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	new->next = NULL;
	new->data.data_length = input->data_length;
	/* freed when operation is aborted (TA_abort_operation) */
	new->data.data = TEE_Malloc(new->data.data_length,
						TEE_MALLOC_FILL_ZERO);
	if (!new->data.data) {
		EMSG("Failed to allocate memory for buffered sign/veify data");
		TEE_Free(new);
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}
	TEE_MemMove(new->data.data, input->data, input->data_length);
	if (current == NULL) {
		operation->sf_item = new;
	} else {
		while (current != NULL) {
			if (current->next == NULL) {
				current->next = new;
				break;
			}
			current = current->next;
		}
	}
	return KM_ERROR_OK;
}

keymaster_error_t TA_append_sf_data(keymaster_blob_t *input,
				const keymaster_operation_t *operation,
				bool *is_input_ext)
{
	uint32_t size = 0;
	uint32_t padding = 0;
	uint8_t *ptr = NULL;
	keymaster_blob_list_item_t *current = operation->sf_item;

	if (operation->sf_item == NULL) {
		if (!(*is_input_ext)) {
			/*
			 * In this case input is stack variable and we need to
			 * allocate memory for next operations.
			 */
			ptr = TEE_Malloc(input->data_length, TEE_MALLOC_FILL_ZERO);
			if (!ptr) {
				EMSG("Failed to allocate memory for input data buffer");
				return KM_ERROR_MEMORY_ALLOCATION_FAILED;
			}
			TEE_MemMove(ptr, input->data, input->data_length);
			*is_input_ext = true;
			input->data = ptr;
		}
		return KM_ERROR_OK;
	}

	while (current != NULL) {
		size += current->data.data_length;
		current = current->next;
	}
	/* Freed before input blob is destroyed */
	ptr = TEE_Malloc(size + input->data_length, TEE_MALLOC_FILL_ZERO);
	if (!ptr) {
		EMSG("Failed to allocate memory on saved blocks append");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	current = operation->sf_item;
	while (current != NULL) {
		TEE_MemMove(ptr + padding, current->data.data,
						current->data.data_length);
		padding += current->data.data_length;
		current = current->next;
	}
	TEE_MemMove(ptr + padding, input->data, input->data_length);
	if (*is_input_ext)
		TEE_Free(input->data);
	input->data = ptr;
	input->data_length = size + input->data_length;
	*is_input_ext = true;
	return KM_ERROR_OK;
}

void TA_add_to_nonce(keymaster_operation_t *operation, const uint64_t value)
{
	uint8_t mask = 0xff;
	uint8_t add;
	uint8_t old_val;
	uint8_t one = 0;
	uint8_t remainder = value;
	uint32_t i = operation->nonce.data_length - 1;

	while (remainder != 0 || one != 0) {
		add = remainder & mask;
		old_val = operation->nonce.data[i];
		operation->nonce.data[i] += add + one;
		one = 0;
		if (old_val > operation->nonce.data[i]) {
			/* uint8_t overflow */
			one = 1;
			if (i == 0) {
				/* 16 byte counter overflow */
				i = operation->nonce.data_length;
			}
		}
		remainder = remainder >> 8;
		i--;
	}
}

void TA_decriment_nonce(keymaster_operation_t *operation)
{
	uint8_t minus_one = 1;
	uint32_t i = operation->nonce.data_length - 1;

	while (minus_one != 0) {
		if (operation->nonce.data[i] > 0) {
			operation->nonce.data[i] -= minus_one;
			minus_one = 0;
		} else {
			operation->nonce.data[i] = 0xff;
			if (i == 0) {
				/* 16 byte counter overflow */
				i = operation->nonce.data_length;
			}
		}
		i--;
	}
}
