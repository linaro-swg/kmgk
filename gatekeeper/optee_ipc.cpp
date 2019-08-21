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

#include <cstring>

#define LOG_TAG "OpteeIPC"
#include <utils/Log.h>

#include <gatekeeper_ipc.h>
#include "optee_ipc.h"

#undef LOG_TAG
#define LOG_TAG "OpteeGatekeeper"

namespace android {
namespace hardware {
namespace gatekeeper {
namespace V1_0 {
namespace optee {

OpteeIPC::OpteeIPC()
    : inUse(false)
{
}

OpteeIPC::~OpteeIPC()
{
    disconnect();
    finalize();
}

bool OpteeIPC::initialize()
{
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        ALOGE("TEEC_InitializeContext failed with code 0x%x", res);
        return false;
    }

    return true;
}

bool OpteeIPC::connect(const TEEC_UUID& uuid)
{
    if (inUse) {
        ALOGE("Is already connected");

        return false;
    }

    TEEC_Result res;

    uint32_t err_origin;
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC,
            NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        ALOGE("TEEC_Opensession failed with code 0x%x origin 0x%x",
            res, err_origin);

        return false;
    }

    inUse = true;

    return true;
}

void OpteeIPC::finalize()
{
    TEEC_FinalizeContext(&ctx);
}

void OpteeIPC::disconnect()
{
    if (inUse) {
        TEEC_CloseSession(&sess);
    }

    inUse = false;
}

bool OpteeIPC::call(uint32_t cmd,
        const uint8_t *in,  uint32_t  in_size,
              uint8_t *out, uint32_t& out_size)
{
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = (void*)in;
    op.params[0].tmpref.size = in_size;

    op.params[1].tmpref.buffer = out;
    op.params[1].tmpref.size = out_size;

    uint32_t err_origin;
    TEEC_Result res = TEEC_InvokeCommand(&sess, cmd, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
	ALOGE("TEEC_InvokeCommand failed with code 0x%08x origin 0x%08x",
		res, err_origin);
	if (res == TEEC_ERROR_TARGET_DEAD) {
		disconnect();
		connect(TA_GATEKEEPER_UUID);
	}
        return false;
    }

    return true;
}

}  // namespace optee
}  // namespace V1_0
}  // namespace gatekeeper
}  // namespace hardware
}  // namespace android
