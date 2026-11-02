# SPDX-License-Identifier: GPL-2.0-only
ifneq ($(KERNELRELEASE),)
obj-m += bashos_auth_stage1.o
bashos_auth_stage1-y := device.o secrets.o
ifeq ($(BASHOS_AUTH_KUNIT_TEST),1)
ifeq ($(filter y m,$(CONFIG_KUNIT)),)
$(error KUnit module requires a prepared kernel with CONFIG_KUNIT=y or m)
endif
obj-m += bashos_auth_stage1_test.o
bashos_auth_stage1_test-y := tests/kunit.o tests/core_under_test.o
endif
else
KDIR ?= /lib/modules/$(shell uname -r)/build
CC ?= cc
CFLAGS ?= -O2 -g
.PHONY: all modules userspace clean
all: modules userspace
modules:
	$(MAKE) -C "$(KDIR)" M="$(CURDIR)" W=1 modules
userspace: tests/abi_check tests/device_test
tests/abi_check: tests/abi_check.c uapi/linux/bashos_auth.h
	$(CC) $(CFLAGS) -std=c11 -Wall -Wextra -Werror -Iuapi $< -o $@
tests/device_test: tests/device_test.c uapi/linux/bashos_auth.h
	$(CC) $(CFLAGS) -std=c11 -Wall -Wextra -Werror -pthread -Iuapi $< -o $@
clean:
	$(MAKE) -C "$(KDIR)" M="$(CURDIR)" clean
	$(RM) tests/abi_check tests/device_test
endif
