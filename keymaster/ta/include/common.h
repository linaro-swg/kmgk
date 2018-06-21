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

#ifndef KEYMASTER_COMMON_H
#define KEYMASTER_COMMON_H

#define SIZE_LENGTH sizeof(uint64_t)
#define SIZE_OF_ITEM(item) (item ? sizeof(item[0]) : 0)
#define PARAM_SET_SIZE(parameters) \
            (SIZE_LENGTH + \
            parameters->length * SIZE_OF_ITEM(parameters->params) \
            + get_blob_size_in_params(parameters))
#define BLOB_SIZE(blob) \
            (blob->data_length * SIZE_OF_ITEM(blob->data) + SIZE_LENGTH)
#define KEY_BLOB_SIZE(key_blob) \
            (key_blob->key_material_size * \
            SIZE_OF_ITEM(key_blob->key_material) + SIZE_LENGTH)
#define TA_KEYMASTER_UUID { 0xdba51a17, 0x0563, 0x11e7, \
		{ 0x93, 0xb1, 0x6f, 0xa7, 0xb0, 0x07, 0x1a, 0x51} }

enum keystore_command {
	KM_ADD_RNG_ENTROPY			= 2,
	KM_GENERATE_KEY				= 3,
	KM_GET_KEY_CHARACTERISTICS		= 4,
	KM_IMPORT_KEY				= 5,
	KM_EXPORT_KEY				= 6,
	KM_ATTEST_KEY				= 7,
	KM_UPGRADE_KEY				= 8,
	KM_DELETE_KEY				= 9,
	KM_DELETE_ALL_KEYS			= 10,
	KM_BEGIN				= 11,
	KM_UPDATE				= 12,
	KM_FINISH				= 13,
	KM_ABORT				= 14,
	KM_DESTROY_ATT_IDS			= 15,
/*
 * Please keep this constant consistent with KM_GET_AUTHTOKEN_KEY define that
 * is defined in Gatekeeper
 */
	KM_GET_AUTHTOKEN_KEY		= 65536,
};

typedef enum{
	KM_NULL					= 0,
	KM_POPULATED				= 1,
} presence;

#endif /* KEYMASTER_COMMON_H */
