CFG_TEE_TA_LOG_LEVEL ?= 2
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

# Enable compatibility with TEE Internal Core API v1.1
CFG_TA_OPTEE_CORE_API_COMPAT_1_1=y

ifeq ($(CFG_ATTESTATION_PROVISIONING), y)
CFLAGS += -DCFG_ATTESTATION_PROVISIONING=1
else
$(warning Provisioning disabled.)
endif

# The UUID for the Trusted Application
BINARY = dba51a17-0563-11e7-93b1-6fa7b0071a51

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
