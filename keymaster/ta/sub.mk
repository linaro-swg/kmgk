global-incdirs-y += include

global-incdirs-y += yaml
subdirs-y += yaml

srcs-y += keystore_ta.c
srcs-y += operations.c
srcs-y += tables.c
srcs-y += parsel.c
srcs-y += master_crypto.c
srcs-y += paddings.c
srcs-y += parameters.c
srcs-y += auth.c
srcs-y += generator.c
srcs-y += asn1.c
srcs-y += crypto_aes.c
srcs-y += crypto_rsa.c
srcs-y += shift.c
srcs-y += crypto_ec.c
srcs-y += attestation.c
