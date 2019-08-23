/*
 * The name of this file must not be modified
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <common.h>

#define TA_UUID TA_KEYMASTER_UUID

#define TA_FLAGS	(TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR | \
			TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION)
#define TA_STACK_SIZE	(32 * 1024)
#define TA_DATA_SIZE	(256 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
	{ "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
		"Keymaster TA" }, \
	{ "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }

#endif /*USER_TA_HEADER_DEFINES_H*/
