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
#include <linux/fs.h>
#include <linux/device.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Fabian Mastenbroek <mail.fabianm@gmail.com>");
MODULE_DESCRIPTION("ubnt-common shim for the UniFi Dream Machine (Pro)");
MODULE_VERSION("1.0");
MODULE_ALIAS("ubnt_common");

static long ubnt_sta_ht_ioctl(struct file *file, unsigned req, unsigned long arg)
{
	/* Unsupported */
	return -ENOSYS;
}

static int ubnt_sta_ht_maj;
static const struct file_operations ubnt_sta_ht_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ubnt_sta_ht_ioctl,
};

int ubnt_sta_ht_init(void)
{
	ubnt_sta_ht_maj = register_chrdev(0, "ubnt_sta_ht", &ubnt_sta_ht_fops);
	if (ubnt_sta_ht_maj < 0) {
		pr_err("Unable to register char device:%s\n", "ubnt_sta_ht");
		return ubnt_sta_ht_maj;
	}
	return 0;
}

void ubnt_sta_ht_exit(void)
{}

static int __init ubnt_common_init(void)
{
	int err = ubnt_sta_ht_init();
	if (err < 0) {
		pr_err("Failed to init sta_ht (%d)", err);
		return err;
	}
	return 0;
}

module_init(ubnt_common_init);

static void __exit ubnt_common_exit(void)
{
	pr_info("Unloading...\n");
	ubnt_sta_ht_exit();
}
module_exit(ubnt_common_exit);
