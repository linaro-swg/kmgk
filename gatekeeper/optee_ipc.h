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

#ifndef OPTEE_IPC_H
#define OPTEE_IPC_H

extern "C" {
#include <tee_client_api.h>
}
namespace android {
namespace hardware {
namespace gatekeeper {
namespace V1_0 {
namespace optee {

class OpteeIPC {
public:
    OpteeIPC();
    ~OpteeIPC();

    bool initialize();
    void finalize();

    bool connect(const TEEC_UUID& uuid);
    void disconnect();
    bool call(uint32_t cmd,
            const uint8_t *in,  uint32_t  in_size,
                  uint8_t *out, uint32_t& out_size);

private:
    TEEC_Context ctx;
    TEEC_Session sess;
    bool inUse;
};
}  // namespace optee
}  // namespace V1_0
}  // namespace gatekeeper
}  // namespace hardware
}  // namespace android

#endif /* OPTEE_IPC_H */
