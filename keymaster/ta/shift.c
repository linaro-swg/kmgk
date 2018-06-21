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
#include "shift.h"

void TA_short_be_rshift(uint8_t *data,
			const uint32_t data_l,
			const uint32_t shift)
{
	uint8_t prev = 0;
	uint8_t next = 0;
	uint32_t wild_shift = BITS_IN_BYTE - shift;

	if (shift > BITS_IN_BYTE || shift <= 0)
		return;
	for (uint32_t i = 0; i < data_l; i++) {
		next = data[i] << wild_shift;
		data[i] >>= shift;
		data[i] |= prev;
		prev = next;
	}
}
