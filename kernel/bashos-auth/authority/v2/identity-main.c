// SPDX-License-Identifier: GPL-2.0-only
/* Production identity protocol v2 module: /dev/bashos-auth-v2, mode 0600.
 * It has no qualification gate, no test ioctl and no fault knob. */
#include <linux/module.h>
#include "identity-device.h"

static const struct ba_v2_identity_variant production = {
	.node = "bashos-auth-v2",
	.info_flags = 0,
};

static int __init identity_init(void)
{
	return ba_v2_identity_device_register(&production);
}

static void __exit identity_exit(void)
{
	ba_v2_identity_device_unregister();
}
module_init(identity_init);
module_exit(identity_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("bash-os identity protocol v2: native-verifier proof and same-fd reference");
