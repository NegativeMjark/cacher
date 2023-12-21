#define _GNU_SOURCE

#include "sha256.c"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define COPY_BUFFER_SIZE 0x200000
#define PROC_FD_PATH_SIZE 64

char const * const hex = "0123456789ABCDEF";

#define write_const(fd, value) write(fd, value, sizeof(value) - 1)


SHA256_CTX ctx;
unsigned char hash[32];
char hexhash[65];
char proc_fd_path[PROC_FD_PATH_SIZE];
struct stat cache_stat;
char * copy_buffer = NULL;


int copy_between_files(int src, int dst, ssize_t count)
{
	struct stat dst_stat;

	if (fstat(dst, &dst_stat) == -1)
	{
		perror("fstat on stdout failed");
		return 1;
	}
	
	while (count > 0)
	{
		ssize_t copy_result; 	
		if (S_ISREG(dst_stat.st_mode))
		{	
			copy_result = copy_file_range(src, NULL, dst, NULL, count, 0);
		}
		else if (S_ISFIFO(dst_stat.st_mode))
		{
			copy_result = splice(src, NULL, dst, NULL, count, 0);
		}
		else
		{
			if (copy_buffer == NULL)
			{
				copy_buffer = (char *) mmap(
					NULL,
					COPY_BUFFER_SIZE,
					PROT_READ | PROT_WRITE,
					MAP_ANONYMOUS | MAP_PRIVATE,
					-1,
					0
				);
				if (copy_buffer == NULL)
				{
					perror("allocating buffer failed");
					return 1;
				}
			}

			size_t r_count = COPY_BUFFER_SIZE;
			if (count < COPY_BUFFER_SIZE)
			{
				r_count = count;
			}
	
			copy_result = read(src, copy_buffer, r_count);
			if (copy_result > 0)
			{
				ssize_t w_count = copy_result;
				while (w_count > 0)
				{
					ssize_t write_result = write(
						dst, copy_buffer + copy_result - w_count, w_count
					);
					if (write_result == -1)
					{
						perror("writing to stdout failed");
						return 1;
					}
					w_count -= write_result;
				}
			}
		}

		if (copy_result == -1)
		{
			perror("reading from cache file failed");
			return 1;
		}
		count -= copy_result;
	}

	return 0;
}


int main(int argc, char * const * const argv)
{
	if (argc < 2)
	{
		ssize_t result = 2;
		result += write_const(STDERR_FILENO, "usage: ");
		result += write(STDERR_FILENO, argv[0], strlen(argv[0]));
		result += write_const(STDERR_FILENO, " cache_dir command [argument ...]\n");
		return result;
	}
	
	int cache_dir_fd = openat(AT_FDCWD, argv[1], O_DIRECTORY | O_PATH | O_CLOEXEC);
	if (cache_dir_fd == -1)
	{
		perror("opening cache dir failed");
		return 1;
	}

	sha256_init(&ctx);
	for (int i = 2; i < argc; i++)
	{
		sha256_update(&ctx, argv[i], 1 + strlen(argv[i]));
	}
	sha256_final(&ctx, hash);

	for (int i = 0; i < 32; i++)
	{
		hexhash[2 * i] = hex[0xF & (hash[i] >> 4)];
		hexhash[2 * i + 1] = hex[0xF & hash[i]];
	}
	hexhash[64] = 0;

	int cache_file_fd = openat(cache_dir_fd, hexhash, O_RDONLY | O_CLOEXEC);
	if (cache_file_fd != -1)
	{	
		if (fstat(cache_file_fd, &cache_stat) == -1)
		{
			perror("fstat on cache file failed");
			return 1;
		}
		return copy_between_files(cache_file_fd, STDOUT_FILENO, cache_stat.st_size);
	}

	if (errno != ENOENT)
	{
		perror("opening cache file failed");
		return 1;
	}

	int pipefds[2];
	if (pipe2(pipefds, 0) == -1)
	{
		perror("creating pipes failed");
		return 1;
	}

	pid_t child_pid = fork();
	if (child_pid == 0)
	{
		if (close(pipefds[0]) == -1)
		{
			perror("closing read pipe failed");
			return 1;
		}
		if (dup3(pipefds[1], STDOUT_FILENO, 0) == -1)
		{
			perror("duplicating write pipe failed");
			return 1;
		}
		if (close(pipefds[1]) == -1)
		{
			perror("closing write pipe failed");
			return 1;
		}

		execvp(argv[2], argv + 2);
		perror("exec failed");
		return 1;
	}

	if (close(pipefds[1]) == -1)
	{
		perror("closing write pipe failed");
		return 1;
	}

	signal(SIGPIPE, SIG_IGN);

	int output_fd = openat(cache_dir_fd, ".", O_TMPFILE | O_RDWR, S_IRUSR);
	if (output_fd == -1)
	{
		perror("opening temporary cache file failed");
		return 1;
	}

	while (1)
	{
		ssize_t copied = splice(pipefds[0], NULL, output_fd, NULL, COPY_BUFFER_SIZE, 0);
		if (copied == -1)
		{
			perror("copying output failed");
			return 1;
		}

		if (copied == 0)
		{
			break;
		}

		if (lseek(output_fd, -copied, SEEK_CUR) == -1)
		{
			perror("seek failed");
			return 1;
		}
	
		if (copy_between_files(output_fd, STDOUT_FILENO, copied))
		{
			return 1;
		}
	}

	siginfo_t child_info;
	if (waitid(P_PID, child_pid, &child_info, WEXITED) == -1)
	{
		perror("wait failed");
		return 1;
	}
	if (child_info.si_code == CLD_EXITED)
	{
		if (child_info.si_status == 0)
		{
			snprintf(proc_fd_path, PROC_FD_PATH_SIZE, "/proc/self/fd/%d", output_fd);
			
			if (linkat(AT_FDCWD, proc_fd_path, cache_dir_fd, hexhash, AT_SYMLINK_FOLLOW) == -1) 
			{
				perror("linking into cache dir failed");
				return 1;
			}
		}
		return child_info.si_status;
	}
	return -child_info.si_status;
}
