#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/uio.h>
#include <linux/export.h>
#include <linux/fsnotify.h>
#include <linux/compat.h>
#include <linux/mount.h>

#include <asm/uaccess.h>

static inline loff_t *file_ppos(struct file *file) {
	return file->f_mode & FMODE_STREAM ? NULL : &file->f_pos;
}

int sys_swrite(int fd, char* buf, int len) {
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;
	loff_t pos, *ppos; 
	int j = 0;

	while(j < len) {
		buf[j] = buf[j] ^ 0b11111111;
		j++;
	}

	if(f.file) {
		ppos = file_ppos(f.file);
		if(ppos) {
			pos = *ppos;
			ppos = &pos;
		}

		ret = vfs_write(f.file, buf, len, ppos);
		if(ret >= 0 && ppos) {
			f.file->f_pos = pos;
		}
		fdput_pos(f);
	}

	return ret;
}

SYSCALL_DEFINE3(swrite, int, fd, char*, buf, int, len) {
	return sys_swrite(fd, buf, len);
}

