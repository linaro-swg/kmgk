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

#ifndef ANDROID_OPTEE_SHIFT_H
#define ANDROID_OPTEE_SHIFT_H

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#define BITS_IN_BYTE 8

/* Right shift of number stored as big endian
 * Short means that max bits to shift is 8
 */
void TA_short_be_rshift(uint8_t *data,
			const uint32_t data_l,
			const uint32_t shift);

#endif/*ANDROID_OPTEE_SHIFT_H*/
