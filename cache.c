
#include "sha256.c"

#ifndef NOLIBC
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

#if STDIN_FILENO != 0
/*
 * Our strategy for writing our cache file is to allocate a tmp file using O_TMPFILE and
 * then link it into position. This is much easier if we know at compile time what fd the
 * tempfile will have then because then the path in /proc/self/fd/%d is a constant string.
 *
 * Openat will always return the lowest unused fd.
 * STDIN has the lowest fd.
 * We don't need STDIN once we've forked out to run the underlying application.
 * Therefore we can close STDIN and use 0 for our output file.
 */
#error "Entirely excessive and unncessary optimisations depend on the STDIN_FILENO being 0"
#endif

/**
 * Ideally we wouldn't need a userspace buffer for copying data between files.
 * However there doesn't seem to be a buffer free way to copy data to a character device in linux.
 * So in that case we will need to allocate a temporary userspace buffer.
 */
#define COPY_BUFFER_SIZE 0x200000
static char * copy_buffer = NULL;

static char const * const HEX_CHARS = "0123456789ABCDEF";
static void hex(unsigned char const * input, char * output, int count)
{
	for (int i = 0; i < count; i++)
	{
		unsigned char c = input[i];
		output[2 * i + 0] = HEX_CHARS[0xF & (c >> 4)];
		output[2 * i + 1] = HEX_CHARS[0xF & c];
	}
}


/**
 * Helper methods for writing strings to a file.
 */
#define write_const(fd, value) write(fd, value, sizeof(value) - 1)
#define write_value(fd, value) write(fd, value, strlen(value))


static ssize_t check_call(size_t value, char const * const message)
{
	if (value == -1)
	{
		perror(message);
		exit(1);
	}
	return value;
}

#define checked(syscall, args) check_call(syscall args, #syscall) 

static void * check_alloc(void * value, char const * const message)
{
	if (value == NULL)
	{
		perror(message);
		exit(1);
	}
	return value;
}


static void copy_file(int src, int dst, ssize_t count)
{
	struct stat dst_stat;

	check_call(fstat(dst, &dst_stat), "fstat");

	while (count > 0)
	{
		ssize_t copy_result;
		if (S_ISREG(dst_stat.st_mode))
		{
			copy_result = checked(copy_file_range, (src, NULL, dst, NULL, count, 0));
		}
		else if (S_ISFIFO(dst_stat.st_mode))
		{
			copy_result = checked(splice, (src, NULL, dst, NULL, count, 0));
		}
		else
		{
			if (copy_buffer == NULL)
			{
				copy_buffer = (char *) check_alloc(mmap(
					NULL,
					COPY_BUFFER_SIZE,
					PROT_READ | PROT_WRITE,
					MAP_ANONYMOUS | MAP_PRIVATE,
					-1,
					0
				), "mmap");
			}

			size_t r_count = COPY_BUFFER_SIZE;
			if (count < COPY_BUFFER_SIZE)
			{
				r_count = count;
			}

			copy_result = checked(read, (src, copy_buffer, r_count));
			if (copy_result > 0)
			{
				ssize_t w_count = copy_result;
				while (w_count > 0)
				{
					w_count -= checked(write, (
						dst, copy_buffer + copy_result - w_count, w_count
					));
				}
			}
		}

		count -= copy_result;
	}
}


#define HASH_LEN 32
static SHA256_CTX ctx;
static unsigned char hash[HASH_LEN];

/* We need names for three files here:
 *  1) The cache file (This will be the hexencoded SHA246 hash of the arguments)
 *  2) A lock file to guard against duplicate creation attempts.
 *  3) A random temporary file to hold the cache file until we can renameat it into place.
 * We will be sneaky and make 1 a suffix of 2 and 2 a suffix of 3.
 * This means we can use a single buffer for all three files.
 * This is a pointless micro optmisation but it's the sort of thing that amuses me.
 */
static char filenames[HASH_LEN * 2 + 1 + HASH_LEN * 2 + 1];
static char * const cache_filename = filenames + HASH_LEN * 2 + 1;
static char * const lock_filename = filenames + HASH_LEN * 2;
static char * const tmp_filename = filenames;
static struct stat cache_stat;
static struct flock lock_flock;
static struct timespec times[2];


void main_check_for_cache(int cache_dir_fd, int lock_fd, time_t cache_duration)
{
	int cache_file_fd = openat(
		cache_dir_fd,
		cache_filename,
		O_RDONLY | O_CLOEXEC | O_NOATIME,
		0
	);
	if (cache_file_fd != -1)
	{
		checked(fstat, (cache_file_fd, &cache_stat));

		if (cache_duration > 0)
		{
			checked(clock_gettime, (CLOCK_TAI, &times[0]));
			if ((times[0].tv_sec > cache_stat.st_mtim.tv_sec + cache_duration)
				|| ((times[0].tv_sec == cache_stat.st_mtim.tv_sec + cache_duration)
					&& times[0].tv_nsec > cache_stat.st_mtim.tv_nsec ))
			{
				return;
			}
		}

		/* Fast path for cached file */
		if (lock_fd != -1)
		{
			lock_flock.l_type = F_UNLCK;
			checked(fcntl, (lock_fd, F_SETLK, &lock_flock));
		}

		copy_file(cache_file_fd, STDOUT_FILENO, cache_stat.st_size);
		exit(0);
	}

	if (errno != ENOENT)
	{
		perror("openat");
		exit(1);
	}
}


time_t main_parse_duration(char * input)
{
	time_t result = 0;
	time_t value = 0;
	char * p = input;
	while(1)
	{
		char c = *(p++);
		if (c == 0)
		{
			return result + value;
		}
		else if (c == 'd' || c == 'D')
		{
			result += value * (24 * 60 * 60);
			value = 0;
		}
		else if (c == 'h' || c == 'H')
		{
			result += value * (60 * 60);
			value = 0;
		}
		else if (c == 'm' || c == 'M')
		{
			result += value * 60;
			value = 0;
		}
		else if (c == 's' || c == 'S')
		{
			result += value;
			value = 0;
		}
		else if ('0' <= c && c <= '9')
		{
			value *= 10;
			value += c - '0';
		}
		else
		{
			ssize_t result = 3;
			result |= write_const(STDERR_FILENO, "invalid duration\n");
			exit(result & 3);
		}
	}
}


#define CACHE_ARGS 3

extern char **environ;

int main(int argc, char * const * const argv)
{
	if (argc < CACHE_ARGS)
	{
		ssize_t result = 2;
		result |= write_const(STDERR_FILENO, "usage: ");
		result |= write_value(STDERR_FILENO, argv[0]);
		result |= write_const(STDERR_FILENO, " cache_dir timeout command [argument ...]\n");
		return result & 2;
	}

	int cache_dir_fd = checked(openat, (AT_FDCWD, argv[1], O_DIRECTORY | O_PATH | O_CLOEXEC, 0));

	time_t cache_duration = main_parse_duration(argv[2]);

	sha256_init(&ctx);
	for (int i = CACHE_ARGS; i < argc; i++)
	{
		sha256_update(&ctx, argv[i], 1 + strlen(argv[i]));
	}
	sha256_final(&ctx, hash);

	hex(hash, cache_filename, HASH_LEN);

	main_check_for_cache(cache_dir_fd, -1, cache_duration);

	lock_filename[0] = '_';
	int lock_fd = checked(openat, (
		cache_dir_fd, lock_filename, O_WRONLY | O_CREAT | O_CLOEXEC, S_IWUSR
	));
	lock_flock.l_type = F_WRLCK;
	lock_flock.l_whence = SEEK_SET;
	lock_flock.l_start = 0;
	lock_flock.l_len = 1;
	checked(fcntl, (lock_fd, F_SETLKW, &lock_flock));

	main_check_for_cache(cache_dir_fd, lock_fd, cache_duration);

	checked(getrandom, (hash, HASH_LEN, 0));
	hex(hash, tmp_filename, HASH_LEN);

	int pipefds[2];
	checked(pipe2, (pipefds, 0));

	checked(clock_gettime, (CLOCK_TAI, &times[0]));

	pid_t child_pid = checked(fork, ());
	if (child_pid == 0)
	{
		checked(close, (pipefds[0]));
		checked(dup3, (pipefds[1], STDOUT_FILENO, 0));
		checked(close, (pipefds[1]));
		checked(execvpe, (argv[CACHE_ARGS], argv + CACHE_ARGS, environ));
	}

	checked(close, (pipefds[1]));

	/* Closing STDIN will free up file descriptor 0 for the output file */
	checked(close, (STDIN_FILENO));
	int output_fd = checked(openat, (cache_dir_fd, ".", O_TMPFILE | O_RDWR, S_IRUSR));

	while (1)
	{
		ssize_t copied = checked(splice, (pipefds[0], NULL, output_fd, NULL, COPY_BUFFER_SIZE, 0));

		if (copied == 0)
		{
			break;
		}

		checked(lseek, (output_fd, -copied, SEEK_CUR));
		copy_file(output_fd, STDOUT_FILENO, copied);
	}

	siginfo_t child_info;
	checked(waitid, (P_PID, child_pid, &child_info, WEXITED));

	if (child_info.si_code == CLD_EXITED)
	{
		if (child_info.si_status == 0)
		{
			checked(unlinkat, (
				cache_dir_fd,
				lock_filename,
				0
			));

			checked(linkat, (
				AT_FDCWD,
				"/proc/self/fd/0",
				cache_dir_fd,
				tmp_filename,
				AT_SYMLINK_FOLLOW
			));

			checked(clock_gettime, (CLOCK_TAI, &times[1]));
			checked(futimens, (output_fd, times));

			checked(renameat, (
				cache_dir_fd,
				tmp_filename,
				cache_dir_fd,
				cache_filename
			));
		}
		return child_info.si_status;
	}
	return -child_info.si_status;
}
