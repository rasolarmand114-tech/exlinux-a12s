/*
 * include/linux/susfs_backport.h
 * #include <linux/susfs_backport.h>
 *
 * Backport implementations for missing SUSFS functions.
 * Included by fs/susfs.c to resolve linker errors on older/custom kernels.
 * 
 * This header code is not part of simonpunk's SuSFS files
 * so don't expect to find this on their repository.
 * 
 * License: GPL 2
 * Note: Only apply this to susfs.c!
 */



#ifndef _LINUX_SUSFS_BACKPORT_H
#define _LINUX_SUSFS_BACKPORT_H

#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/fs_struct.h>

/* security/selinux/avc.c (KSU)
 *
 * Determine the missing AVC Log spoofing
 * Some KSU managers like rsuntk does not define the AVC log spoofing as intended
 * by gki patch, however, we instead define it here so there is minimal intervention from
 * any side whatsoever
 * 
*/

#ifdef CONFIG_KSU_SUSFS
// This variable is declared extern in susfs.c but defined in security/selinux/avc.c in 6.12-gki patch.
// We define it here to satisfy the linker.
bool susfs_is_avc_log_spoofing_enabled = false;
#endif

/* fs/readdir.c
 *
 * We define susfs_sus_ino_for_filldir64 to prevent errors at fs/readdir.c
 * 
 * 
*/

#ifdef CONFIG_KSU_SUSFS_SUS_PATH

// We need access to the helper functions usually static in susfs.c
// Since this header is included at the END of susfs.c, it can see them.
// Note: These prototypes essentially just confirm availability to the compiler.
extern bool is_i_uid_in_android_data_not_allowed(uid_t i_uid);
extern bool is_i_uid_in_sdcard_not_allowed(void);

int susfs_sus_ino_for_filldir64(unsigned long ino) {
	struct st_susfs_sus_path_list *cursor = NULL;

	// Check Android Data paths
	list_for_each_entry(cursor, &LH_SUS_PATH_ANDROID_DATA, list) {
		if (cursor->info.target_ino == ino && is_i_uid_in_android_data_not_allowed(cursor->info.i_uid)) {
			return 1; // Hide this entry
		}
	}

	// Check SDCard paths
	list_for_each_entry(cursor, &LH_SUS_PATH_SDCARD, list) {
		if (cursor->info.target_ino == ino && is_i_uid_in_sdcard_not_allowed()) {
			return 1; // Hide this entry
		}
	}
	
	// Check Loop paths
	list_for_each_entry(cursor, &LH_SUS_PATH_LOOP, list) {
		if (cursor->info.target_ino == ino) {
			 // Standard behavior is to hide these loop files
			 return 1;
		}
	}

	return 0; // Do not hide
}
#endif /* CONFIG_KSU_SUSFS_SUS_PATH */

/* kernelsu/setuid_hook.c
 *
 *
 * We define susfs_reorder_mnt_id to satisfy the setuid and mount
 * 
 */

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT

// We assume struct mount is available via "mount.h" included in susfs.c
// If specific fields like susfs_mnt_id_backup are missing in struct vfsmount,
// you must ensure include/linux/mount.h is patched first.

void susfs_reorder_mnt_id(void) {
	struct mnt_namespace *mnt_ns = current->nsproxy->mnt_ns;
	struct mount *mnt;
	struct rb_node *node;
	int first_mnt_id = 0;

	if (!mnt_ns) {
		return;
	}

	// Optimization: In original patch, we check atomic64_read(&susfs_ksu_mounts).
	// Since we might not track that counter in this backport, we skip the check
	// and run the reorder logic safely anyway.

	get_mnt_ns(mnt_ns);

	node = mnt_ns->mounts.rb_node;
	if (!node) {
		goto out_put_mnt_ns;
	}

	first_mnt_id = node_to_mount(node)->mnt_id;

	for (; node; node = rb_next(node)) {
		mnt = node_to_mount(node);
		if (mnt->mnt_id == DEFAULT_KSU_MNT_ID) {
			continue;
		}
		// Backup the original ID and assign the new ordered ID
		WRITE_ONCE(mnt->mnt.susfs_mnt_id_backup, READ_ONCE(mnt->mnt_id));
		WRITE_ONCE(mnt->mnt_id, first_mnt_id++);
	}

out_put_mnt_ns:
	put_mnt_ns(mnt_ns);
}
#endif /* CONFIG_KSU_SUSFS_SUS_MOUNT */

#endif /* _LINUX_SUSFS_BACKPORT_H */