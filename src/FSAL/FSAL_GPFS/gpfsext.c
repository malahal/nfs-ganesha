/*-------------------------------------------------------------------------
 * NAME:        gpfs_ganesha()
 *
 * FUNCTION:    Use ioctl to call into the GPFS kernel module.
 *              If GPFS isn't loaded they receive ENOSYS.
 *
 * Returns:      0      Successful
 *              -1      Failure
 *
 * Errno:       ENOSYS  No quality of service function available
 *              ENOENT  File not found
 *              EINVAL  Not a GPFS file
 *              ESTALE  cached fs information was invalid
 *-------------------------------------------------------------------------*/

#include "config.h"

#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdio.h>

#ifdef _VALGRIND_MEMCHECK
#include <valgrind/memcheck.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include "include/gpfs.h"
#endif

#include "common_utils.h"
#include "abstract_atomic.h"

#include "include/gpfs_nfs.h"

struct kxArgs {
	signed long arg1;
	signed long arg2;
};

#ifdef _VALGRIND_MEMCHECK
static void valgrind_kganesha(struct kxArgs *args)
{
	int op = (int)args->arg1;

	switch (op) {
	case OPENHANDLE_STATFS_BY_FH:
	{
		struct statfs_arg *arg = (void *)args->arg2;

		VALGRIND_MAKE_MEM_DEFINED(arg->buf, sizeof(*arg->buf));
		break;
	}
	case OPENHANDLE_READ_BY_FD:
	{
		struct read_arg *arg = (void *)args->arg2;

		VALGRIND_MAKE_MEM_DEFINED(arg->bufP, arg->length);
		break;
	}
	case OPENHANDLE_NAME_TO_HANDLE:
	{
		struct name_handle_arg *arg = (void *)args->arg2;

		VALGRIND_MAKE_MEM_DEFINED(arg->handle->f_handle,
					  arg->handle->handle_size);
		break;
	}
	case OPENHANDLE_GET_HANDLE:
	{
		struct get_handle_arg *arg = (void *)args->arg2;

		VALGRIND_MAKE_MEM_DEFINED(arg->out_fh->f_handle,
					  arg->out_fh->handle_size);
		break;
	}
	case OPENHANDLE_STAT_BY_NAME:
	{
		struct stat_name_arg *arg = (void *)args->arg2;

		VALGRIND_MAKE_MEM_DEFINED(arg->buf, sizeof(*arg->buf));
		break;
	}
	case OPENHANDLE_CREATE_BY_NAME:
	{
		struct create_name_arg *arg = (void *)args->arg2;

		VALGRIND_MAKE_MEM_DEFINED(arg->new_fh->f_handle,
					  arg->new_fh->handle_size);
		break;
	}
	case OPENHANDLE_READLINK_BY_FH:
	{
		struct readlink_fh_arg *arg = (void *)args->arg2;

		VALGRIND_MAKE_MEM_DEFINED(arg->buffer, arg->size);
		break;
	}
	case OPENHANDLE_GET_XSTAT:
	{
		struct xstat_arg *arg = (void *)args->arg2;

		VALGRIND_MAKE_MEM_DEFINED(arg->buf, sizeof(*arg->buf));
		VALGRIND_MAKE_MEM_DEFINED(arg->fsid, sizeof(*arg->fsid));
		if (arg->acl) {
			struct gpfs_acl *gacl;
			size_t outlen;

			/*
			 * arg->acl points to an IN/OUT buffer. First
			 * few fields are initialized by the caller and
			 * the rest are filled in by the ioctl call.
			 */
			gacl = arg->acl;
			outlen = gacl->acl_len -
				offsetof(struct gpfs_acl, acl_nace);
			VALGRIND_MAKE_MEM_DEFINED(&gacl->acl_nace, outlen);
		}
		break;
	}
	case OPENHANDLE_WRITE_BY_FD:
	{
		struct write_arg *arg = (void *)args->arg2;

		VALGRIND_MAKE_MEM_DEFINED(arg->stability_got,
					  sizeof(*arg->stability_got));
		break;
	}
	default:
		break;
	}
}
#endif

struct gpfs_stats {
	uint64_t resp_time;
	uint64_t num_ops;
	uint64_t resp_time_max;
	uint64_t resp_time_min;
} gpfs_stats[200];

int gpfs_ganesha(int op, void *oarg)
{
	int rc;
	static int gpfs_fd = -1;
	struct kxArgs args;
	struct timespec start_time;
	struct timespec stop_time;
	nsecs_elapsed_t resp_time;

	if (gpfs_fd < 0) {
		gpfs_fd = open(GPFS_DEVNAMEX, O_RDONLY);
		if (gpfs_fd < 0) {
			fprintf(stderr,
				"Ganesha call to GPFS failed with ENOSYS\n");
			return ENOSYS;
		}
		(void)fcntl(gpfs_fd, F_SETFD, FD_CLOEXEC);
	}

	args.arg1 = op;
	args.arg2 = (long)oarg;
#ifdef _VALGRIND_MEMCHECK
	valgrind_kganesha(&args);
#endif
	now(&start_time);
	rc = ioctl(gpfs_fd, kGanesha, &args);
	now(&stop_time);
	resp_time = timespec_diff(&start_time, &stop_time);

	/* record FSAL stats */
	(void)atomic_inc_uint64_t(&gpfs_stats[op].num_ops);
	(void)atomic_add_uint64_t(&gpfs_stats[op].resp_time, resp_time);
	if (gpfs_stats[op].resp_time_max < resp_time)
		gpfs_stats[op].resp_time_max = resp_time;
	if (gpfs_stats[op].resp_time_min == 0 ||
	    gpfs_stats[op].resp_time_min > resp_time)
		gpfs_stats[op].resp_time_min = resp_time;

	return rc;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
void dump_gpfs_fsal_stats()
{
	FILE *fp;
	int op;

	fp = fopen("/tmp/fsal.stats", "w");
	if (fp == NULL)
		return;

	/* less than 100 should be empty */
	for (op = 100; op < ARRAY_SIZE(gpfs_stats); op++) {
		if (gpfs_stats[op].num_ops)
			fprintf(fp,
				"op:%u, num:%lu, resp:%lu, resp_min:%lu, resp_max:%lu\n",
				op, gpfs_stats[op].num_ops,
				gpfs_stats[op].resp_time,
				gpfs_stats[op].resp_time_min,
				gpfs_stats[op].resp_time_max);
	}
	fclose(fp);
}
