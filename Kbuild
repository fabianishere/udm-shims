ifneq ($(KBUILD_EXTMOD),)
CONFIG_UBNT_UBNTHAL := m
CONFIG_UBNT_GPIODEV := m
endif

obj-$(CONFIG_UBNT_GPIODEV) += gpiodev-shim.o
obj-$(CONFIG_UBNT_UBNTHAL) += ubnthal-shim.o