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

#ifndef FAILURE_RECORD_H
#define FAILURE_RECORD_H

#include <stdint.h>
#include <stdbool.h>
#include "ta_gatekeeper.h"

/*
 * Structure is a failure table entry
 */
typedef struct {
	secure_id_t secure_user_id;
	uint64_t last_checked_timestamp;
	uint32_t failure_counter;
} failure_record_t;

/*
 * Initialize failure record table
 */
void InitFailureRecords(void);

/*
 * Returns failure @record for secure @user_id
 */
void GetFailureRecord(secure_id_t user_id, failure_record_t *record);

/*
 * Write failure @record to failure record table. Function will rewrite the
 * oldest record if failure record table is full
 */
void WriteFailureRecord(const failure_record_t *record);

/*
 * Increment failure counter for @record and set new @timestamp
 */
void IncrementFailureRecord(failure_record_t *record, uint64_t timestamp);

/*
 * Clean failure record counter and timestamp for @user_id
 */
void ClearFailureRecord(secure_id_t user_id);

/*
 * Calculates the timeout in milliseconds as a function of the failure
 * counter 'x' for @record as follows:
 *
 * [0. 5) -> 0
 * 5 -> 30
 * [6, 10) -> 0
 * [11, 30) -> 30
 * [30, 140) -> 30 * (2^((x - 30)/10))
 * [140, inf) -> 1 day
 *
 */
uint32_t ComputeRetryTimeout(const failure_record_t *record);

/*
 * @return current secure timestamp
 */
uint64_t GetTimestamp(void);

/*
 * Function checks if current @record has @response_timeout if current time
 * is @timestamp
 *
 * @return true if response_timeout is not 0
 */
bool ThrottleRequest(failure_record_t *record, uint64_t timestamp,
		uint32_t *response_timeout);

#endif /* FAILURE_RECORD_H */
