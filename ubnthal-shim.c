/*
 * ubnthal-shim
 *
 * Copyright (C) 2022 Fabian Mastenbroek.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define MODULE_NAME "ubnthal-shim"
#define pr_fmt(fmt) MODULE_NAME ": " fmt

#include <linux/ctype.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/mtd/mtd.h>
#include <linux/etherdevice.h>
#include <crypto/hash.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Fabian Mastenbroek <mail.fabianm@gmail.com>");
MODULE_DESCRIPTION("HAL shim for the UniFi Dream Machine (Pro)");
MODULE_VERSION("1.0");
MODULE_ALIAS("ubnthal");

#define PROC_DIR "ubnthal-shim" /* Proc directory where the shim is located */

/**
 * Radio information for Ubiquiti devices.
 */
struct ubnt_radio {
	char *name;
	char *dev;
};

/**
 * Hard-coded device information.
 */
static struct ubnt_device {
	short id;
	char full_name[32];
	char short_name[32];
	char radio_count;
	struct ubnt_radio radio[2];
} ubnt_devices[] = {
	{
		.id = 0xea11,
		.full_name = "UniFi Dream Machine",
		.short_name = "UDM",
		.radio_count = 2,
		.radio = {
			{ .name = "MT7603", .dev = "ra0" },
			{ .name = "MT7603", .dev = "rai0" } },
	},
	{
		.id = 0xea15,
	  	.full_name = "UniFi Dream Machine PRO",
		.short_name = "UDMPRO",
		.radio_count = 0,
		.radio = {}
	}
};

/**
 * Static system information gathered at the start of the module.
 */
static struct ubnthal_sysinfo {
	u32 cpu_type;
	u32 cpu_id;
	u64 flash_size;
	u64 ram_size;
	u16 format;
	u16 version;
	u16 vendor_id;
	u16 system_id;
	u32 board_revision;
	u16 manufacturer_id;
	u64 manufacturer_date;
	struct ubnt_device *device;
	u8 serialno[6];
	u8 qrid[8];
	u16 regdmn[8];
	u64 hashid;
	u64 hash[8];

	int eth_count;
	u8 eth_mac[12][6];

	int wifi_count;
	u8 wifi_mac[4][6];

	int bt_count;
	u8 bt_mac[2][6];
} ubnthal_sysinfo = { 0 };

/**
 * Mutable status information of the interface.
 */
static struct ubnthal_status {
	/**
	 * The hostname of the controller.
	 */
	char host[128];

	/**
	 * The port at which the controller is accessible.
	 */
	int port;

	/**
	 * Device flags
	 */
	int is_default;
	int is_isolated;
	int is_located;
	int is_lte;
} ubnthal_status = { .host = "localhost", .port = 8080 };

/* Routines for accessing static information */
struct ubnt_device *ubnthal_get_device(short id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ubnt_devices); i++) {
		struct ubnt_device *device = &ubnt_devices[i];
		if (device->id == id) {
			return device;
		}
	}

	return NULL;
}

/* Hashing */
struct ubnthal_sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct ubnthal_sdesc *_ubnthal_sha256_init(struct crypto_shash *alg)
{
	int size = sizeof(struct ubnthal_sdesc) + crypto_shash_descsize(alg);
	struct ubnthal_sdesc *sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc) {
		return ERR_PTR(-ENOMEM);
	}
	sdesc->shash.tfm = alg;
	return sdesc;
}

static int _ubnthal_sha256_hash(struct crypto_shash *alg, const void *data,
				size_t size, void *digest)
{
	struct ubnthal_sdesc *sdesc;
	int ret;

	sdesc = _ubnthal_sha256_init(alg);
	if (IS_ERR(sdesc)) {
		pr_info("Unable to allocate sdesc\n");
		return PTR_ERR(sdesc);
	}

	ret = crypto_shash_digest(&sdesc->shash, data, size, digest);
	kfree(sdesc);
	return ret;
}

static int ubnthal_sha256_hash(u8 *serialno, u64 hashid, void *digest)
{
	int ret;
	struct crypto_shash *alg;
	char input[14];

	alg = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(alg)) {
		pr_info("Unable to allocate algorithm sha256\n");
		return PTR_ERR(alg);
	}

	// Initialize input
	memcpy(input, serialno, 6);
	memcpy(input + 6, &hashid, 8);

	ret = _ubnthal_sha256_hash(alg, input, 14, digest);
	crypto_free_shash(alg);
	return ret;
}

/* Routines for parsing the EEPROM */

/**
 * EEPROM data layout.
 */
struct ubnt_eeprom {
	u8 header[4];
	u32 checksum;
	u32 size;
	u16 format;
	u16 version;
	u16 vendor_id;
	u16 system_id;
	u32 board_revision;
	u8 serialno[6];
	u8 eth_count;
	u8 wifi_count;
	u16 regdmn[8];
	u8 _padding_1[64];
	u8 bt_count;
} __attribute__((packed));

void alpine_compute_mac(char *serialno, char *mac, int i)
{
	u64 u = ether_addr_to_u64(serialno) + i;
	u64_to_ether_addr(u, mac);
}

int alpine_read_eeprom(struct mtd_info *mtd, void *data, size_t count,
		       loff_t *off)
{
	int ret = 0;
	size_t retlen = 0;

	while (count) {
		ret = mtd_read(mtd, *off, count, &retlen, data);
		if (!ret || (ret == -EUCLEAN) || (ret == -EBADMSG)) {
			off += retlen;
			count -= retlen;
			data += retlen;
			if (retlen == 0) {
				count = 0;
			}
		} else {
			return ret;
		}
	}

	return 0;
}

int alpine_scan_eeprom(struct ubnthal_sysinfo *sysinfo)
{
	int err = 0;
	int ret, i, mac_idx;
	size_t size;
	loff_t off;
	void *data;
	struct mtd_info *mtd;
	struct ubnt_eeprom *base;
	struct ubnt_device *device;

	mtd = get_mtd_device_nm("EEPROM");
	if (IS_ERR(mtd)) {
		return PTR_ERR(mtd);
	}

	size = 0x10000;
	data = kmalloc(size, GFP_KERNEL);

	if (!data) {
		err = -ENOMEM;
		goto out_1;
	}

	off = 0;
	ret = alpine_read_eeprom(mtd, data, size, &off);
	if (ret) {
		err = ret;
		goto out_2;
	}

	base = data + 0x8000;

	if (memcmp(base->header, "UBNT", 4) != 0) {
		pr_warn("EEPROM header mismatch: got %01x%01x%01x%01x\n",
			base->header[0], base->header[1], base->header[2],
			base->header[3]);
	}

	sysinfo->format = be16_to_cpu(base->format);
	sysinfo->version = be16_to_cpu(base->version);
	sysinfo->vendor_id = be16_to_cpu(base->vendor_id);
	sysinfo->system_id = be16_to_cpu(base->system_id);
	sysinfo->board_revision = be32_to_cpu(base->board_revision);

	memcpy(sysinfo->serialno, base->serialno, 6);
	for (i = 0; i < ARRAY_SIZE(base->regdmn); i++) {
		sysinfo->regdmn[i] = be16_to_cpu(base->regdmn[i]);
	}

	mac_idx = 0;
	sysinfo->eth_count = base->eth_count;
	for (i = 0; i < sysinfo->eth_count; i++) {
		alpine_compute_mac(sysinfo->serialno, sysinfo->eth_mac[i],
				   mac_idx++);
	}

	sysinfo->wifi_count = base->wifi_count;
	for (i = 0; i < sysinfo->wifi_count; i++) {
		alpine_compute_mac(sysinfo->serialno, sysinfo->wifi_mac[i],
				   mac_idx++);
	}

	sysinfo->bt_count = base->bt_count;
	for (i = 0; i < sysinfo->bt_count; i++) {
		alpine_compute_mac(sysinfo->serialno, sysinfo->bt_mac[i],
				   mac_idx++);
	}

	device = ubnthal_get_device(sysinfo->system_id);
	if (device != NULL) {
		sysinfo->device = device;
		pr_info("Detected Ubiquiti %s\n", device->full_name);
	}

	/* Other fields are located at different places */
	sysinfo->manufacturer_id = be16_to_cpu(*((u16 *)(data + 0xA002)));
	sysinfo->manufacturer_date = be64_to_cpu(*((u64 *)(data + 0xA014)));
	sysinfo->hashid = *((u64 *)(data + 0xe040));
	memcpy(sysinfo->qrid, data + 0xa0bb, 6);
	sysinfo->qrid[6] = 0;
out_2:
	kfree(data);
out_1:
	put_mtd_device(mtd);
	return err;
}

u32 alpine_get_cpu_rev_id(void)
{
	u32 *data = ioremap(0xfd8a815c, 4);
	u32 res = *data;
	rmb();
	iounmap(data);
	return res;
}

u32 alpine_get_cpuid(void)
{
	return alpine_get_cpu_rev_id() ^ read_cpuid_id();
}

u32 alpine_get_cputype(void)
{
	u32 res = alpine_get_cpuid();
	if (res != 0x411ed073) {
		res = 0xffffffff;
	}
	return res;
}

u64 alpine_get_flashsize(void)
{
	/* Hardcoded into kernel module */
	return 0x1000000;
}

u64 alpine_get_ramsize(void)
{
	struct sysinfo i;
	si_meminfo(&i);

	return (i.totalram * 0x1000 + 0x3fffffff) & 0xffffffffc0000000;
}

static int ubnthal_system_init(void)
{
	int ret;

	ubnthal_sysinfo.cpu_id = alpine_get_cpuid();
	ubnthal_sysinfo.cpu_type = alpine_get_cputype();
	ubnthal_sysinfo.flash_size = alpine_get_flashsize();
	ubnthal_sysinfo.ram_size = alpine_get_ramsize();

	ret = alpine_scan_eeprom(&ubnthal_sysinfo);
	if (ret) {
		return ret;
	}

	ret = ubnthal_sha256_hash(ubnthal_sysinfo.serialno,
				  ubnthal_sysinfo.hashid, ubnthal_sysinfo.hash);
	if (ret) {
		return ret;
	}
	ubnthal_sysinfo.hashid = ubnthal_sysinfo.hash[3];

	return 0;
}

static void ubnthal_system_exit(void)
{
}

/* proc entries */
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_dir_orig;
static struct proc_dir_entry *proc_status_dir;

static int show_boolean(struct seq_file *fp, int value)
{
	switch (value) {
	case 0:
		seq_printf(fp, "false\n");
		break;
	case 1:
		seq_printf(fp, "true\n");
		break;
	default:
		seq_printf(fp, "unknown\n");
		break;
	}
	return 0;
}

static int parse_boolean(const char __user *s, size_t count, bool *res)
{
	char buf[6];
	int r;

	count = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, s, count)) {
		return -EFAULT;
	}
	buf[count] = '\0';

	r = strncasecmp("true", buf, 4);
	if (!r) {
		*res = 1;
		return 0;
	}

	r = strncasecmp("false", buf, 5);
	if (!r) {
		*res = 0;
		return 0;
	}

	return -EINVAL;
}

static int tm_isoweek(struct tm *tm, u64 timestamp)
{
	int epoch_year = mktime(tm->tm_year + 1900, tm->tm_mon, 1, 0, 0, 0);
	int days = epoch_year / 86400 + 4; // Days since epoch (plus four days)
	int offset = epoch_year - (days - (days / 7) * 7) * 86400;

	return (timestamp - offset) / 604800 + 1; // Convert to weeks
}

/* /proc/ubnthal/.uf */
static ssize_t write_flash_protection(struct file *file, const char __user *buf,
				      size_t count, loff_t *offset)
{
	/* Ignore any data written, since we don't implement flash protection */
	return count;
}

static struct proc_dir_entry *proc_flash_protection;
static struct file_operations proc_flash_protection_file_fops = {
	.owner = THIS_MODULE,
	.write = write_flash_protection,
};

/* /proc/ubnthal/board */
static int show_board(struct seq_file *fp, void *v)
{
	int i;

	seq_printf(fp, "format=%04d\n", (u16)ubnthal_sysinfo.format);
	seq_printf(fp, "version=%04d\n", (u16)ubnthal_sysinfo.version);
	seq_printf(fp, "boardid=%04x\n", (u16)ubnthal_sysinfo.system_id);
	seq_printf(fp, "vendorid=%04x\n", (u16)ubnthal_sysinfo.vendor_id);
	seq_printf(fp, "bomrev=%04x%04x\n",
		   (u16)(ubnthal_sysinfo.board_revision >> 16),
		   (u16)ubnthal_sysinfo.board_revision);
	seq_printf(fp, "hwaddrbbase=%pM\n", ubnthal_sysinfo.serialno);
	seq_printf(fp, "EthMACAddrCount=%d\n", ubnthal_sysinfo.eth_count);
	seq_printf(fp, "WiFiMACAddrCount=%d\n", ubnthal_sysinfo.wifi_count);
	seq_printf(fp, "BtMACAddrCount=%d\n", ubnthal_sysinfo.bt_count);

	for (i = 0; i < 8; i++) {
		seq_printf(fp, "regdmn[%d]=%04x\n", i,
			   (u16)ubnthal_sysinfo.regdmn[i]);
	}

	return 0;
}

static int open_board(struct inode *inode, struct file *file)
{
	return single_open(file, show_board, NULL);
}

static struct proc_dir_entry *proc_board;
static struct file_operations proc_board_file_fops = {
	.owner = THIS_MODULE,
	.open = open_board,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* /proc/ubnthal/system.info */
static int show_system_info(struct seq_file *fp, void *v)
{
	int i;
	struct tm tm;
	struct ubnt_device *device = ubnthal_sysinfo.device;
	u8 *hashid = (u8 *)&ubnthal_sysinfo.hashid;
	u8 *anonid = (u8 *)&ubnthal_sysinfo.hash;

	seq_printf(fp, "cpu=%s\n", "AL324V2");
	seq_printf(fp, "cpuid=%08x\n", (u32)ubnthal_sysinfo.cpu_id);
	seq_printf(fp, "flashSize=%llu\n", ubnthal_sysinfo.flash_size);
	seq_printf(fp, "ramsize=%llu\n", ubnthal_sysinfo.ram_size);
	seq_printf(fp, "vendorid=%04x\n", (u16)ubnthal_sysinfo.vendor_id);
	seq_printf(fp, "systemid=%04x\n", (u16)ubnthal_sysinfo.system_id);
	seq_printf(fp, "shortname=%s\n",
		   device ? ubnthal_sysinfo.device->short_name : "UNKNOWN");
	seq_printf(fp, "boardrevision=%x\n",
		   ubnthal_sysinfo.board_revision & 0xFF);
	seq_printf(fp, "serialno=%pm\n", ubnthal_sysinfo.serialno);
	seq_printf(fp, "manufid=%04x\n", (u16)ubnthal_sysinfo.manufacturer_id);

	time64_to_tm(ubnthal_sysinfo.manufacturer_date, 0, &tm);
	seq_printf(fp, "mfgweek=%04ld%02d\n", 1900 + tm.tm_year,
		   tm_isoweek(&tm, ubnthal_sysinfo.manufacturer_date));

	seq_printf(fp, "qrid=%s\n", ubnthal_sysinfo.qrid);

	for (i = 0; i < ubnthal_sysinfo.eth_count; i++) {
		seq_printf(fp, "eth%d.macaddr=%pM\n", i,
			   ubnthal_sysinfo.eth_mac[i]);
	}

	if (device) {
		for (i = 0; i < device->radio_count; i++) {
			seq_printf(fp, "radio%d.name=%s\n", i,
				   device->radio[i].name);
		}
	}

	seq_printf(fp, "device.hashid=%02x%02x%02x%02x%02x%02x%02x%02x\n",
		   hashid[0], hashid[1], hashid[2], hashid[3], hashid[4],
		   hashid[5], hashid[6], hashid[7]);
	seq_printf(
		fp,
		"device.anonid=%02x%02x%02x%02x-%02x%02x-4%02x%1x-8%1x%02x-%02x%02x%02x%02x%02x%02x\n",
		(u8)anonid[17], (u8)anonid[18], (u8)anonid[19], (u8)anonid[20],
		(u8)anonid[21], (u8)anonid[22], (u8)anonid[23],
		(u8)(anonid[24] >> 4) & 0xF, (u8)anonid[24] & 0xF,
		(u8)anonid[25], (u8)anonid[26], (u8)anonid[27], (u8)anonid[28],
		(u8)anonid[29], (u8)anonid[30], (u8)anonid[31]);

	if (device) {
		for (i = 0; i < ubnthal_sysinfo.wifi_count; i++) {
			seq_printf(fp, "%s.macaddr=%pM\n", device->radio[i].dev,
				   ubnthal_sysinfo.wifi_mac[i]);
		}
	}

	for (i = 0; i < ubnthal_sysinfo.bt_count; i++) {
		seq_printf(fp, "bt%d.macaddr=%pM\n", i,
			   ubnthal_sysinfo.bt_mac[i]);
	}

	seq_printf(fp, "regdmn[]=");
	for (i = 0; i < ARRAY_SIZE(ubnthal_sysinfo.regdmn); i++) {
		seq_printf(fp, "%04x", (u16)ubnthal_sysinfo.regdmn[i]);
	}
	seq_printf(fp, "\n");

	seq_printf(fp, "cpu_rev_id=%08x\n", (u32)alpine_get_cpu_rev_id());
	return 0;
}

static int open_system_info(struct inode *inode, struct file *file)
{
	return single_open(file, show_system_info, NULL);
}

static struct proc_dir_entry *proc_system_info;
static struct file_operations proc_system_info_file_fops = {
	.owner = THIS_MODULE,
	.open = open_system_info,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* /proc/ubnthal/status/ControllerHost */
static int show_controller_host(struct seq_file *fp, void *v)
{
	seq_printf(fp, "%s\n", ubnthal_status.host);
	return 0;
}

static int open_controller_host(struct inode *inode, struct file *file)
{
	return single_open(file, show_controller_host, NULL);
}

static ssize_t write_controller_host(struct file *file, const char __user *buf,
				     size_t count, loff_t *offset)
{
	return count;
}

static struct proc_dir_entry *proc_controller_host;
static struct file_operations proc_controller_host_file_fops = {
	.owner = THIS_MODULE,
	.open = open_controller_host,
	.read = seq_read,
	.write = write_controller_host,
	.llseek = seq_lseek,
	.release = single_release,
};

/* /proc/ubnthal/status/ControllerPort */
static int show_controller_port(struct seq_file *fp, void *v)
{
	seq_printf(fp, "%d\n", ubnthal_status.port);
	return 0;
}

static int open_controller_port(struct inode *inode, struct file *file)
{
	return single_open(file, show_controller_port, NULL);
}

static ssize_t write_controller_port(struct file *file, const char __user *buf,
				     size_t count, loff_t *offset)
{
	return count;
}

static struct proc_dir_entry *proc_controller_port;
static struct file_operations proc_controller_port_file_fops = {
	.owner = THIS_MODULE,
	.open = open_controller_port,
	.read = seq_read,
	.write = write_controller_port,
	.llseek = seq_lseek,
	.release = single_release,
};

/* /proc/ubnthal/status/IsDefault */
static int show_is_default(struct seq_file *fp, void *v)
{
	return show_boolean(fp, ubnthal_status.is_default);
}

static int open_is_default(struct inode *inode, struct file *file)
{
	return single_open(file, show_is_default, NULL);
}

static ssize_t write_is_default(struct file *file, const char __user *buf,
				size_t count, loff_t *off)
{
	bool res = false;
	int ret = parse_boolean(buf, count, &res);

	if (ret) {
		return ret;
	}

	ubnthal_status.is_default = res;

	*off = count;
	return count;
}

static struct proc_dir_entry *proc_is_default;
static struct file_operations proc_is_default_file_fops = {
	.owner = THIS_MODULE,
	.open = open_is_default,
	.read = seq_read,
	.write = write_is_default,
	.llseek = seq_lseek,
	.release = single_release,
};

/* /proc/ubnthal/status/IsIsolated */
static int show_is_isolated(struct seq_file *fp, void *v)
{
	return show_boolean(fp, ubnthal_status.is_isolated);
}

static int open_is_isolated(struct inode *inode, struct file *file)
{
	return single_open(file, show_is_isolated, NULL);
}

static ssize_t write_is_isolated(struct file *file, const char __user *buf,
				 size_t count, loff_t *off)
{
	bool res = false;
	int ret = parse_boolean(buf, count, &res);

	if (ret) {
		return ret;
	}

	ubnthal_status.is_isolated = res;

	*off = count;
	return count;
}

static struct proc_dir_entry *proc_is_isolated;
static struct file_operations proc_is_isolated_file_fops = {
	.owner = THIS_MODULE,
	.open = open_is_isolated,
	.read = seq_read,
	.write = write_is_isolated,
	.llseek = seq_lseek,
	.release = single_release,
};

/* /proc/ubnthal/status/IsLocated */
static int show_is_located(struct seq_file *fp, void *v)
{
	return show_boolean(fp, ubnthal_status.is_located);
}

static int open_is_located(struct inode *inode, struct file *file)
{
	return single_open(file, show_is_located, NULL);
}

static ssize_t write_is_located(struct file *file, const char __user *buf,
				size_t count, loff_t *off)
{
	bool res = false;
	int ret = parse_boolean(buf, count, &res);

	if (ret) {
		return ret;
	}

	ubnthal_status.is_located = res;

	*off = count;
	return count;
}

static struct proc_dir_entry *proc_is_located;
static struct file_operations proc_is_located_file_fops = {
	.owner = THIS_MODULE,
	.open = open_is_located,
	.read = seq_read,
	.write = write_is_located,
	.llseek = seq_lseek,
	.release = single_release,
};

/* /proc/ubnthal/status/IsLte */
static int show_is_lte(struct seq_file *fp, void *v)
{
	return show_boolean(fp, ubnthal_status.is_lte);
}

static int open_is_lte(struct inode *inode, struct file *file)
{
	return single_open(file, show_is_lte, NULL);
}

static ssize_t write_is_lte(struct file *file, const char __user *buf,
			    size_t count, loff_t *off)
{
	bool res = false;
	int ret = parse_boolean(buf, count, &res);

	if (ret) {
		return ret;
	}

	ubnthal_status.is_lte = res;

	*off = count;
	return count;
}

static struct proc_dir_entry *proc_is_lte;
static struct file_operations proc_is_lte_file_fops = {
	.owner = THIS_MODULE,
	.open = open_is_lte,
	.read = seq_read,
	.write = write_is_lte,
	.llseek = seq_lseek,
	.release = single_release,
};

static int ubnthal_proc_init(void)
{
	int ubnthal_active;

	pr_info("Creating entry at /proc/%s\n", PROC_DIR);
	proc_dir = proc_mkdir(PROC_DIR, NULL);

	if (!proc_dir) {
		pr_err("Failed to create /proc/%s\n", PROC_DIR);
		return -ENOMEM;
	}

	proc_status_dir = proc_mkdir("status", proc_dir);
	if (!proc_status_dir) {
		pr_err("Unable to create /proc/%s/%s\n", PROC_DIR, "status");
		return -ENOMEM;
	}

	proc_flash_protection = proc_create(".uf", S_IWUSR | S_IRUGO, proc_dir,
					    &proc_flash_protection_file_fops);
	if (!proc_flash_protection) {
		pr_err("Unable to create /proc/%s/.uf\n", PROC_DIR);
	}

	proc_board = proc_create("board", S_IWUSR | S_IRUGO, proc_dir,
				 &proc_board_file_fops);
	if (!proc_board) {
		pr_err("Unable to create /proc/%s/board\n", PROC_DIR);
	}

	proc_system_info = proc_create("system.info", S_IWUSR | S_IRUGO,
				       proc_dir, &proc_system_info_file_fops);
	if (!proc_system_info) {
		pr_err("Unable to create /proc/%s/system.info\n", PROC_DIR);
	}

	proc_controller_host =
		proc_create("ControllerHost", S_IWUSR | S_IRUGO,
			    proc_status_dir, &proc_controller_host_file_fops);
	if (!proc_controller_host) {
		pr_err("Unable to create /proc/%s/status/%s\n", PROC_DIR,
		       "ControllerHost");
	}

	proc_controller_port =
		proc_create("ControllerPort", S_IWUSR | S_IRUGO,
			    proc_status_dir, &proc_controller_port_file_fops);
	if (!proc_controller_port) {
		pr_err("Unable to create /proc/%s/status/%s\n", PROC_DIR,
		       "ControllerPort");
	}

	proc_is_default =
		proc_create("IsDefault", S_IWUSR | S_IRUGO, proc_status_dir,
			    &proc_is_default_file_fops);
	if (!proc_is_default) {
		pr_err("Unable to create /proc/%s/status/%s\n", PROC_DIR,
		       "IsDefault");
	}

	proc_is_isolated =
		proc_create("IsIsolated", S_IWUSR | S_IRUGO, proc_status_dir,
			    &proc_is_isolated_file_fops);
	if (!proc_is_isolated) {
		pr_err("Unable to create /proc/%s/status/%s\n", PROC_DIR,
		       "IsIsolated");
	}

	proc_is_located =
		proc_create("IsLocated", S_IWUSR | S_IRUGO, proc_status_dir,
			    &proc_is_located_file_fops);
	if (!proc_is_located) {
		pr_err("Unable to create /proc/%s/status/%s\n", PROC_DIR,
		       "IsLocated");
	}

	proc_is_lte = proc_create("IsLte", S_IWUSR | S_IRUGO, proc_status_dir,
				  &proc_is_lte_file_fops);
	if (!proc_is_lte) {
		pr_err("Unable to create /proc/%s/status/%s\n", PROC_DIR,
		       "IsLte");
	}

	/* Create a symlink from /proc/ubnthal to the shim */
	mutex_lock(&module_mutex);
	ubnthal_active = find_module("ubnthal") != NULL;
	mutex_unlock(&module_mutex);

	if (ubnthal_active) {
		proc_dir_orig = NULL;
		pr_warn("ubnthal is already active...\n");
	} else {
		proc_dir_orig = proc_symlink("ubnthal", NULL, PROC_DIR);
		if (!proc_dir_orig) {
			pr_warn("Unable to create /proc/ubnthal symlink\n");
		}
	}

	return 0;
}

static void ubnthal_proc_exit(void)
{
	if (!proc_dir) {
		return;
	}

	if (proc_flash_protection) {
		proc_remove(proc_flash_protection);
	}

	if (proc_board) {
		proc_remove(proc_board);
	}

	if (proc_system_info) {
		proc_remove(proc_system_info);
	}

	if (proc_controller_host) {
		proc_remove(proc_controller_host);
	}

	if (proc_controller_port) {
		proc_remove(proc_controller_port);
	}

	if (proc_is_default) {
		proc_remove(proc_is_default);
	}

	if (proc_is_isolated) {
		proc_remove(proc_is_isolated);
	}

	if (proc_is_located) {
		proc_remove(proc_is_located);
	}

	if (proc_is_lte) {
		proc_remove(proc_is_lte);
	}

	if (proc_status_dir) {
		proc_remove(proc_status_dir);
	}

	if (proc_dir_orig) {
		proc_remove(proc_dir_orig);
	}

	proc_remove(proc_dir);
}

static int __init ubnthal_init(void)
{
	int err = ubnthal_system_init();
	if (err < 0) {
		pr_err("Failed to system (%d)", err);
		return err;
	}

	err = ubnthal_proc_init();
	if (err < 0) {
		pr_err("Failed to initialize /proc entries (%d)", err);
		return err;
	}

	return 0;
}

module_init(ubnthal_init);

static void __exit ubnthal_exit(void)
{
	pr_info("Unloading...\n");

	ubnthal_proc_exit();
	ubnthal_system_exit();
}
module_exit(ubnthal_exit);
