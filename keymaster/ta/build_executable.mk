#
# Copyright (C) 2017 GlobalLogic
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Android build top/root directory
ANDROID_ROOT            := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../../..)

TA_OUT_INTERMEDIATES    := $(ANDROID_ROOT)/$(OUT_DIR)/target/product/$(TARGET_PRODUCT)/obj/TA_OBJ
OPTEE_OUT               := $(ANDROID_ROOT)/$(OUT_DIR)/target/product/$(TARGET_PRODUCT)/obj/OPTEE_OBJ

OPTEE_CROSS_COMPILE     := $(ANDROID_ROOT)/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-gnu-7.1.1/bin/aarch64-linux-gnu-

###########################################################
## Rules for building Trusted Application (TA)           ##
## executable file.                                      ##
###########################################################

ifeq ($(TA_UUID),)
$(error TA_UUID variable is not set)
endif

ifeq ($(TA_SRC),)
$(error TA_SRC variable is not set)
endif

# TA intermediates output folder
TA_OUT := $(TA_OUT_INTERMEDIATES)/$(TA_UUID)_OBJ

# OP-TEE TA developer kit
export TA_DEV_KIT_DIR := $(OPTEE_OUT)/export-ta_arm64

# OP-TEE Trusted OS is dependency for TA
.PHONY: tee.bin
$(TA_OUT): tee.bin
	mkdir -p $@

TA_TARGET:=$(TA_UUID)_ta
.PHONY: $(TA_TARGET)

# Parameters for target TA
TA_UUID-$(TA_TARGET):=$(TA_UUID)
TA_SRC-$(TA_TARGET):=$(TA_SRC)
TA_OUT-$(TA_TARGET):=$(TA_OUT)

# Build with OP-TEE Trusted OS build system
$(TA_TARGET): $(TA_OUT)
	CROSS_COMPILE=$(OPTEE_CROSS_COMPILE) BINARY=$(TA_UUID-$@) make -C $(TA_SRC-$@) O=$(TA_OUT-$@) clean
	CROSS_COMPILE=$(OPTEE_CROSS_COMPILE) BINARY=$(TA_UUID-$@) make -C $(TA_SRC-$@) O=$(TA_OUT-$@) all

# Include into AOSP build system
include $(CLEAR_VARS)

# TA output file
TA_BIN_PATH := $(TA_OUT)/$(TA_UUID).ta
$(TA_BIN_PATH): $(TA_TARGET)

LOCAL_MODULE := $(TA_UUID).ta
LOCAL_PREBUILT_MODULE_FILE:= $(TA_BIN_PATH)

# TA folder on device
LOCAL_MODULE_PATH := $(TARGET_OUT_VENDOR_SHARED_LIBRARIES)/optee_armtz

include $(BUILD_EXECUTABLE)
