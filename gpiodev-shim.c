/*
 * gpiodev-shim
 *
 * Copyright (C) 2021 Fabian Mastenbroek.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define MODULE_NAME "gpiodev-shim"
#define pr_fmt(fmt) MODULE_NAME ": " fmt

#include <linux/ctype.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/timer.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Fabian Mastenbroek <mail.fabianm@gmail.com>");
MODULE_DESCRIPTION("LED control shim for the UniFi Dream Machine (Pro)");
MODULE_VERSION("1.0");
MODULE_ALIAS("gpiodev");

#define PROC_DIR "gpiodev-shim" /* Proc directory where the shim is located */

extern void ledtrig_external(int, unsigned);

/* LED control */
static void gpio_update_led(struct timer_list *);
static DEFINE_TIMER(led_timer, gpio_update_led);

static int led_tempo = 120;
static int led_status = 0;
static int led_pattern_len = 0;
static int led_current_note = 0;
static unsigned led_pattern[128];

static int gpio_init_led(void)
{
	int tempo = led_tempo != 0 ? 15000 / led_tempo : 0;
	return mod_timer(&led_timer, jiffies + tempo);
}

static void gpio_exit_led(void)
{
	del_timer(&led_timer);
}

static void gpio_set_led(unsigned int color)
{
	ledtrig_external(0, color & 2);
	ledtrig_external(1, color & 1);
}

static void gpio_update_led(struct timer_list *unused)
{
	unsigned color = led_pattern[led_current_note];
	if (color != led_status) {
		led_status = color;
		gpio_set_led(color);
	}

	if (led_pattern_len > 1) {
		int tempo = led_tempo != 0 ? 15000 / led_tempo : 0;
		led_current_note = (led_current_note + 1) % led_pattern_len;
		mod_timer(&led_timer, jiffies + tempo);
	}
}

/* proc entries */
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_dir_orig;

static ssize_t write_ledbar_control(struct file *file, const char __user *buf,
				    size_t count, loff_t *offset)
{
	/* Not implemented on UDM/P */
	return -ENOSYS;
}

static struct proc_dir_entry *proc_ledbar_control;
static struct file_operations proc_ledbar_control_file_fops = {
	.owner = THIS_MODULE,
	.write = write_ledbar_control,
};

static int show_led_pattern(struct seq_file *fp, void *v)
{
	int i;
	for (i = 0; i < led_pattern_len; i++) {
		seq_printf(fp, "%1d", led_pattern[i]);
	}
	seq_printf(fp, "\n");
	return 0;
}

static int open_led_pattern(struct inode *inode, struct file *file)
{
	return single_open(file, show_led_pattern, NULL);
}

static ssize_t write_led_pattern(struct file *file, const char __user *buf,
				 size_t count, loff_t *off)
{
	char kbuf[128];
	int new_pattern[128];
	int i, j;
	unsigned color = 0;

	if (copy_from_user(kbuf, buf, min(count, 128ul))) {
		return -EFAULT;
	}

	for (i = 0; i < count && j < 128; i++) {
		int c = kbuf[i];
		if (!isalnum(c)) {
			continue;
		}

		color = c - 0x30; /* Convert ASCII digit to number */
		if (color > 9) {
			color = toupper(c) -
				0x37; /* Convert ASCII hex representation to number */

			if (color < 10 || color >= 16) {
				/* Ignore invalid hex values */
				continue;
			}
		}

		new_pattern[j++] = color;
	}

	if (led_pattern_len != j ||
	    memcmp(led_pattern, new_pattern, j * sizeof(int)) != 0) {
		del_timer(&led_timer);
		memcpy(led_pattern, new_pattern, j * sizeof(int));

		led_current_note = 0;
		led_pattern_len = j;

		gpio_update_led(NULL);
	}

	*off = j;
	return j;
}

static struct proc_dir_entry *proc_led_pattern;
static struct file_operations proc_led_pattern_file_fops = {
	.owner = THIS_MODULE,
	.open = open_led_pattern,
	.read = seq_read,
	.write = write_led_pattern,
	.llseek = seq_lseek,
	.release = single_release,
};

static int show_led_tempo(struct seq_file *fp, void *v)
{
	seq_printf(fp, "%d (beats per minute)\n", led_tempo);
	return 0;
}

static int open_led_tempo(struct inode *inode, struct file *file)
{
	return single_open(file, show_led_tempo, NULL);
}

static ssize_t write_led_tempo(struct file *file, const char __user *buf,
			       size_t count, loff_t *off)
{
	int res = led_tempo;
	int ret = kstrtoint_from_user(buf, count, 10, &res);

	if (ret) {
		return ret;
	}

	if (led_tempo != res) {
		led_tempo = res;
		mod_timer(&led_timer, jiffies + 15000 / res);
	}

	*off = count;
	return count;
}

static struct proc_dir_entry *proc_led_tempo;
static struct file_operations proc_led_tempo_file_fops = {
	.owner = THIS_MODULE,
	.open = open_led_tempo,
	.read = seq_read,
	.write = write_led_tempo,
	.llseek = seq_lseek,
	.release = single_release,
};

static int show_poe_passthrough(struct seq_file *fp, void *v)
{
	seq_printf(fp, "%d (%d=off, %d=on)\n", 0, 0, 1);
	return 0;
}

static int open_poe_passthrough(struct inode *inode, struct file *file)
{
	return single_open(file, show_poe_passthrough, NULL);
}

static ssize_t write_poe_passthrough(struct file *file, const char __user *buf,
				     size_t count, loff_t *offset)
{
	return -ENOSYS;
}

static struct proc_dir_entry *proc_poe_passthrough;
static struct file_operations proc_poe_passthrough_file_fops = {
	.owner = THIS_MODULE,
	.open = open_poe_passthrough,
	.read = seq_read,
	.write = write_poe_passthrough,
	.llseek = seq_lseek,
	.release = single_release,
};

static int gpio_init_proc(void)
{
	int gpiodev_active;
	pr_info("Creating entry at /proc/%s\n", PROC_DIR);
	proc_dir = proc_mkdir(PROC_DIR, NULL);

	if (!proc_dir) {
		pr_err("Failed to create /proc/%s\n", PROC_DIR);
		return -ENOMEM;
	}

	proc_ledbar_control =
		proc_create("ledbar_control", S_IWUSR | S_IRUGO, proc_dir,
			    &proc_ledbar_control_file_fops);
	if (!proc_ledbar_control) {
		pr_err("Unable to create /proc/%s/%s\n", PROC_DIR,
		       "ledbar_control");
	}

	proc_led_pattern = proc_create("led_pattern", S_IWUSR | S_IRUGO,
				       proc_dir, &proc_led_pattern_file_fops);
	if (!proc_led_pattern) {
		pr_err("Unable to create /proc/%s/%s\n", PROC_DIR,
		       "led_pattern");
	}

	proc_led_tempo = proc_create("led_tempo", S_IWUSR | S_IRUGO, proc_dir,
				     &proc_led_tempo_file_fops);
	if (!proc_led_tempo) {
		pr_err("Unable to create /proc/%s/%s\n", PROC_DIR, "led_tempo");
	}

	proc_poe_passthrough =
		proc_create("poe_passthrough", S_IWUSR | S_IRUGO, proc_dir,
			    &proc_poe_passthrough_file_fops);
	if (!proc_poe_passthrough) {
		pr_err("Unable to create /proc/%s/%s\n", PROC_DIR,
		       "poe_passthrough");
	}

	/* Create a symlink from /proc/gpio to the shim */
	mutex_lock(&module_mutex);
	gpiodev_active = find_module("gpiodev") != NULL;
	mutex_unlock(&module_mutex);

	if (gpiodev_active) {
		proc_dir_orig = NULL;
		pr_warn("gpiodev is already active...\n");
	} else {
		proc_dir_orig = proc_symlink("gpio", NULL, PROC_DIR);
		if (!proc_dir_orig) {
			pr_warn("Unable to create /proc/gpio symlink\n");
		}
	}

	return 0;
}

static void gpio_exit_proc(void)
{
	if (!proc_dir) {
		return;
	}

	if (proc_ledbar_control) {
		proc_remove(proc_ledbar_control);
	}

	if (proc_led_pattern) {
		proc_remove(proc_led_pattern);
	}

	if (proc_led_tempo) {
		proc_remove(proc_led_tempo);
	}

	if (proc_poe_passthrough) {
		proc_remove(proc_poe_passthrough);
	}

	proc_remove(proc_dir);
}

static int __init gpiodev_init(void)
{
	int err = gpio_init_led();
	if (err < 0) {
		pr_err("Failed to initialize LED (%d)", err);
		return err;
	}

	err = gpio_init_proc();
	if (err < 0) {
		pr_err("Failed to initialize /proc entries (%d)", err);
		return err;
	}

	return 0;
}

module_init(gpiodev_init);

static void __exit gpiodev_exit(void)
{
	pr_info("Unloading...\n");

	gpio_exit_led();
	gpio_exit_proc();
}
module_exit(gpiodev_exit);
