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

#include <string.h>
#include <tee_internal_api.h>
#include "failure_record.h"

#define MAX_FAILURE_RECORDS 32

typedef struct {
	uint32_t size;
	failure_record_t records[MAX_FAILURE_RECORDS];
} failure_record_table_t;

static failure_record_table_t failureRecordTable;


void InitFailureRecords(void)
{
	memset(&failureRecordTable, 0, sizeof(failureRecordTable));
}


void GetFailureRecord(secure_id_t user_id, failure_record_t *record)
{
	uint32_t i;
	failure_record_t *records = failureRecordTable.records;
	uint32_t tableSize = failureRecordTable.size;

	for (i = 0; i < tableSize; i++) {
		if (records[i].secure_user_id == user_id) {
			*record = records[i];
			return;
		}
	}

	record->secure_user_id = user_id;
	record->failure_counter = 0;
	record->last_checked_timestamp = 0;
}


void WriteFailureRecord(const failure_record_t *record)
{
	uint32_t i;
	failure_record_t *records = failureRecordTable.records;

	int min_idx = 0;
	uint64_t min_timestamp = ~0ULL;

	for (i = 0; i < failureRecordTable.size; i++) {
		if (records[i].secure_user_id == record->secure_user_id) {
			break;
		}

		if (records[i].last_checked_timestamp <= min_timestamp) {
			min_timestamp = records[i].last_checked_timestamp;
			min_idx = i;
		}
	}

	if (i >= MAX_FAILURE_RECORDS) {
		// replace the oldest element if all records are in use
		i = min_idx;
	} else if (i == failureRecordTable.size) {
		failureRecordTable.size++;
	}

	records[i] = *record;
}


void IncrementFailureRecord(failure_record_t *record, uint64_t timestamp)
{
	record->failure_counter++;
	record->last_checked_timestamp = timestamp;

	WriteFailureRecord(record);
}


void ClearFailureRecord(secure_id_t user_id)
{
	failure_record_t record;

	record.secure_user_id = user_id;
	record.last_checked_timestamp = 0;
	record.failure_counter = 0;

	WriteFailureRecord(&record);
}


uint32_t ComputeRetryTimeout(const failure_record_t *record)
{
	static const int FAILURE_TIMEOUT_MS = 30000;
	static const int DAY_IN_MS = 1000 * 60 * 60 * 24;

	uint32_t failure_counter = record->failure_counter;

	if (failure_counter == 0) {
		return 0;
	}

	if (failure_counter > 0 && failure_counter <= 10) {
		if (failure_counter % 5 == 0) {
			return FAILURE_TIMEOUT_MS;
		} else {
			return 0;
		}
	} else if (failure_counter < 30) {
		return FAILURE_TIMEOUT_MS;
	} else if (failure_counter < 140) {
		return FAILURE_TIMEOUT_MS << ((failure_counter - 30)/10);
	}
	return DAY_IN_MS;
}


uint64_t GetTimestamp(void)
{
	TEE_Time secure_time;
	TEE_GetSystemTime(&secure_time);
	return secure_time.seconds*1000 + secure_time.millis;
}


bool ThrottleRequest(failure_record_t *record, uint64_t timestamp,
		uint32_t *response_timeout)
{
	uint64_t last_checked = record->last_checked_timestamp;
	uint32_t timeout = ComputeRetryTimeout(record);

	if (timeout > 0) {
		// we have a pending timeout
		if (timestamp < last_checked + timeout &&
				timestamp > last_checked) {
			// attempt before timeout expired, return remaining time
			*response_timeout = timeout - (timestamp-last_checked);
			return true;
		} else if (timestamp <= last_checked) {
			// device was rebooted or timer reset, don't count as
			// new failure but reset timeout
			record->last_checked_timestamp = timestamp;
			WriteFailureRecord(record);
			*response_timeout = timeout;
			return true;
		}
	}

	return false;
}
