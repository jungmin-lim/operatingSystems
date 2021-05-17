#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>

#include <asm/segment.h>
#include <asm/uaccess.h>

static inline loff_t *file_ppos(struct file *file) {
	return file->f_mode & FMODE_STREAM ? NULL : &file->f_pos;
}

int sys_sread(int fd, char *buf, int len) {
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF, j = 0;
	loff_t pos, *ppos;

	if(f.file) {
		ppos = file_ppos(f.file);
		if(ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_read(f.file, buf, len, ppos);
		if(ret >= 0 && ppos) {
			f.file->f_pos = pos;
		}
		fdput_pos(f);
	}

	while(j < ret) {
		buf[j] = buf[j] ^ 0b11111111;
		j++;
	}

	return ret;
}

SYSCALL_DEFINE3(sread, int, fd, char *, buf, int, len) {
	return sys_sread(fd, buf, len);
}
