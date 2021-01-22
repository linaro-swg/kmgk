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

# Include only for HiKey ones in space separated list
# E.g. hikey hikey960 hikey970
# Temporarily disable so that this can be built on multiple platforms
#ifneq (,$(filter $(TARGET_PRODUCT), hikey))
LOCAL_PATH:= $(call my-dir)

################################################################################
# Build keymaster HAL                                                          #
################################################################################
include $(CLEAR_VARS)

LOCAL_MODULE := android.hardware.keymaster@3.0-service.optee
LOCAL_INIT_RC := 3.0/android.hardware.keymaster@3.0-service.optee.rc
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_MODULE_TAGS := optional
LOCAL_VENDOR_MODULE := true

LOCAL_CFLAGS = -Wall -Werror
LOCAL_CFLAGS += -DANDROID_BUILD

LOCAL_SRC_FILES := \
	3.0/service.cpp \
	3.0/optee_keymaster3_device.cpp \
	ipc/optee_keymaster_ipc.cpp \
	optee_keymaster.cpp

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/include

LOCAL_SHARED_LIBRARIES := \
	libteec \
	liblog \
	libhidlbase \
	libhidltransport \
	libhardware \
	libutils \
	libcutils \
	libkeymaster_messages \
	libkeymaster3device \
	android.hardware.keymaster@3.0

include $(BUILD_EXECUTABLE)

################################################################################
# Build wait_for_keymaster_optee
################################################################################
include $(CLEAR_VARS)

LOCAL_MODULE := wait_for_keymaster_optee
LOCAL_INIT_RC := wait/wait_for_keymaster_optee.rc
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_MODULE_TAGS := optional
LOCAL_VENDOR_MODULE := true

LOCAL_CFLAGS = -Wall -Werror -Wextra -Wno-missing-field-initializers -Wno-unused-parameter \
	-Wno-unused-variable
LOCAL_CFLAGS += -DANDROID_BUILD

LOCAL_SRC_FILES := \
	wait/wait_for_keymaster_optee.cpp

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/wait

LOCAL_SHARED_LIBRARIES := \
	libbase \
	libbinder \
	android.hardware.keymaster@3.0 \
	android.hardware.keymaster@4.0 \
	libhardware \
	libhardware_legacy \
	libhidlbase \
	libhwbinder \
	libkeymaster4support \
	libutils

include $(BUILD_EXECUTABLE)

################################################################################
# Build keymaster HAL TA                                                       #
################################################################################
include $(LOCAL_PATH)/ta/Android.mk

#endif # Include only for HiKey ones.
