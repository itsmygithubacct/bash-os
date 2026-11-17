// SPDX-License-Identifier: GPL-2.0-only
/* Production PRIVCMD protocol v2 module: /dev/bashos-privcmd-v2, mode 0666.
 * It has no qualification gate and no fault control. */
#include <linux/module.h>
#include "privcmd-device.h"

static const struct ba_v2_privcmd_variant production = {
	.node = "bashos-privcmd-v2",
	.info_flags = 0,
};

static int __init privcmd_init(void)
{
	return ba_v2_privcmd_device_register(&production);
}

static void __exit privcmd_exit(void)
{
	ba_v2_privcmd_device_unregister();
}
module_init(privcmd_init);
module_exit(privcmd_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("bash-os PRIVCMD protocol v2: pinned policy, native verifier, supervised executor, audit");
