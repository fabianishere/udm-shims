/*
 * ubnt_common-shim
 *
 * Copyright (C) 2022 Fabian Mastenbroek.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define MODULE_NAME "ubnt-common-shim"
#define pr_fmt(fmt) MODULE_NAME ": " fmt

#include <linux/err.h>
#include <linux/module.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Fabian Mastenbroek <mail.fabianm@gmail.com>");
MODULE_DESCRIPTION("ubnt-common shim for the UniFi Dream Machine (Pro)");
MODULE_VERSION("1.0");

static int __init ubnt_common_init(void)
{
	return 0;
}

module_init(ubnt_common_init);

static void __exit ubnt_common_exit(void)
{
	pr_info("Unloading...\n");
}
module_exit(ubnt_common_exit);
