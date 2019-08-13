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

#include "tables.h"

static keymaster_use_timer_t use_timers[KM_MAX_USE_TIMERS];
static keymaster_use_counter_t use_counters[KM_MAX_USE_COUNTERS];
static uint32_t in_use_c;

static void clean_timers(void)
{
	TEE_Time cur_t;

	TEE_GetSystemTime(&cur_t);
	for (uint32_t i = 0; i < KM_MAX_USE_TIMERS; i++) {
		if (use_timers[i].last_access.seconds != 0 &&
			    (cur_t.seconds >=
			    use_timers[i].last_access.seconds +
			    use_timers[i].min_sec)) {
			TEE_MemFill(use_timers[i].key_id, 0,
					sizeof(use_timers[i].key_id));
			use_timers[i].min_sec = 0;
			use_timers[i].last_access.seconds = 0;
			use_timers[i].last_access.millis = 0;
		}
	}
}

keymaster_error_t TA_count_key_uses(const keymaster_key_blob_t key,
				const uint32_t max_uses)
{
	if (in_use_c < KM_MAX_USE_COUNTERS) {
		use_counters[in_use_c].key = key;
		use_counters[in_use_c].count = 0;
		in_use_c++;
	} else {
		return KM_ERROR_TOO_MANY_OPERATIONS;
	}

	for (uint32_t i = 0; i < in_use_c; i++) {
		if (key.key_material_size !=
				use_counters[i].key.key_material_size)
			continue;
		if (!TEE_MemCompare(key.key_material,
				use_counters[i].key.key_material,
				key.key_material_size)) {
			if (use_counters[i].count < max_uses) {
				use_counters[i].count++;
				break;
			}
			EMSG("Reached max key use count!");
			return KM_ERROR_KEY_MAX_OPS_EXCEEDED;
		}
	}
	return KM_ERROR_OK;
}

keymaster_error_t TA_check_key_use_timer(uint8_t *key_id,
					const uint32_t min_sec)
{
	TEE_Time cur_t;
	uint32_t free_n = KM_MAX_USE_TIMERS;

	clean_timers();
	TEE_GetSystemTime(&cur_t);
	for (uint32_t i = 0; i < KM_MAX_USE_TIMERS; i++) {
		if (free_n == KM_MAX_USE_TIMERS &&
			use_timers[i].min_sec == 0) {
			free_n = i;
		}

		if (!TEE_MemCompare(key_id,
				use_timers[i].key_id,
				sizeof(use_timers[i].key_id))) {
			if (use_timers[i].last_access.seconds +
						min_sec > cur_t.seconds) {
				return KM_ERROR_KEY_RATE_LIMIT_EXCEEDED;
			}
			return KM_ERROR_OK;
		}
	}

	if (free_n == KM_MAX_USE_TIMERS) {
		EMSG("Table of last access key time is full");
		return KM_ERROR_TOO_MANY_OPERATIONS;
	}

	memcpy(use_timers[free_n].key_id, key_id,
		sizeof(use_timers[free_n].key_id));
	use_timers[free_n].min_sec = min_sec;

	return KM_ERROR_OK;
}

keymaster_error_t TA_trigger_timer(uint8_t *key_id)
{
	TEE_Time cur_t;

	clean_timers();
	TEE_GetSystemTime(&cur_t);

	for (uint32_t i = 0; i < KM_MAX_USE_TIMERS; i++) {
		if (!TEE_MemCompare(key_id,
				use_timers[i].key_id,
				sizeof (use_timers[i].key_id))) {
			use_timers[i].last_access = cur_t;
			return KM_ERROR_OK;
		}
	}

	return KM_ERROR_OK;
}
