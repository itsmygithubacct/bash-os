// SPDX-License-Identifier: GPL-2.0-only
/* Qualification wrapper of the PRIVCMD protocol v2 device, for disposable
 * guests only: a separately named node, an explicit load-time opt-in and two
 * denial-only fault controls. None of this file is linked into production. */
#include <linux/module.h>
#include "safeedit.h"
#include "privcmd-device.h"
#include "../../uapi/linux/bashos_privcmd_v2.h"

static bool test_only;
module_param(test_only, bool, 0400);
MODULE_PARM_DESC(test_only, "Required explicit opt-in; disposable qualification guest only");
/* Denial-only qualification control. Immutable at module load, absent from
 * production Kbuild, and never substitutes an allow/authentication result. */
static int test_edit_fail_index = -1;
module_param(test_edit_fail_index, int, 0400);
/* Fail RESET alone after normal framing/audit admission. This gives the
 * consumer ordering control a working PREPARE/RUN positive control in the
 * same module instance. It cannot mint a grant or alter a policy decision. */
static bool test_reset_fail;
module_param(test_reset_fail, bool, 0400);

static bool test_edit_fault(u32 index)
{
	return test_edit_fail_index >= 0 && index == (u32)test_edit_fail_index;
}

static bool test_reset_fault(void)
{
	return test_reset_fail;
}

static const struct ba_v2_privcmd_variant qualification = {
	.node = "bashos-privcmd-v2-test",
	.info_flags = BASHOS_PRIVCMD_V2_QUALIFICATION_ONLY,
	.edit_fault = test_edit_fault,
	.reset_fault = test_reset_fault,
};

static int __init privcmd_test_init(void)
{
	if (!test_only || !ba_v2_privcmd_administrator()) return -EPERM;
	if (test_edit_fail_index < -1 || test_edit_fail_index >= (int)BA_V2_EDIT_MAX_TARGETS) return -EINVAL;
	return ba_v2_privcmd_device_register(&qualification);
}

static void __exit privcmd_test_exit(void)
{
	ba_v2_privcmd_device_unregister();
}
module_init(privcmd_test_init);
module_exit(privcmd_test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable PRIVCMD v2 qualification endpoint; production features off");
