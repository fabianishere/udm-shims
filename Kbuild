ifneq ($(KBUILD_EXTMOD),)
CONFIG_UBNT_GPIODEV := m
CONFIG_UBNT_UBNTHAL := m
CONFIG_UBNT_UBNT_COMMON := m
endif

obj-$(CONFIG_UBNT_GPIODEV) += gpiodev-shim.o
obj-$(CONFIG_UBNT_UBNTHAL) += ubnthal-shim.o
obj-$(CONFIG_UBNT_UBNT_COMMON) += ubnt-common-shim.o