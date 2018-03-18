//userapp.c
#include "userapp.h"
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#define PROC_TIME 47
#define PROC_FILE "/proc/mp2/status"

 // * params: the pid, period(ms) and process time(ms) for the task to be registered
 // * return: on success, return the number of bytes written; on failure return a negative number
int reg(pid_t pid, unsigned long period, unsigned long proc_time)
{
    FILE * fp = fopen (PROC_FILE, "a+");
    if(!fp)
    {
        perror ("file doesn't exist\n");
        return -1;
    }
    int byte_write = fprintf(fp, "R, %d, %lu, %lu", pid, period, proc_time);
    fclose(fp);
    return byte_write;
}




 // * params: the pid for the task to be unregistered
 // * return: on success, return the number of bytes written; on failure return a negative number
int unreg(pid_t pid)
{
    FILE * fp = fopen (PROC_FILE, "a+");
    if(!fp)
    {
        perror ("file doesn't exist\n");
        return -1;
    }
    int byte_write = fprintf(fp, "D, %d", pid);
    fclose(fp);
    return byte_write;
}

// * params: the pid for the task to be unregistered
// * return: on success, return the number of bytes written; on failure return a negative number
int yield(pid_t pid)
{
	FILE * fp = fopen(PROC_FILE, "a+");
	if(!fp) {
		perror("file doesn't exist\n");
		return -1;
	}
	int byte_write = fprintf(fp, "Y, %d", pid);
	fclose(fp);
	return byte_write;
}


// The self-defined job for each task to do
// Correct return result should be 0
int do_job(void)
{
    int n = 10000000, ret = 0, i;

    for(i = 0; i < n; i++) {
        ret = ret++;
    }

	for(i = 0; i < n; i++) {
		ret = ret--;
	}
	return ret;
}


// check if the pid is existing in our proc file
int check_status(pid_t pid)
{
    ssize_t read;
    char *line = NULL;
    size_t len = 0;
    char *pid_buf;
    FILE * fp = fopen(PROC_FILE, "r+");
    if(!fp) {
        perror("file doesn't exist\n");
        return -1;
    }

	while ((read = getline(&line, &len, fp)) != -1) {
        pid_buf = strtok(line, ":");
        if(atoi(pid_buf) == pid) {
        	return 0;
        }
    }

    return -1;
}



int main(int argc, char* argv[])
{
    unsigned long per = strtoul(argv[1], NULL, 10);
	pid_t pid = getpid();
    int i, ret;
	long int wakeup_time, job_process_time;
    struct timeval t0, t1;
	time_t current_time;

	if(argc < 2)
    {
    	perror("Number of arguments wrong, please follow: ./userapp [period]\n");
        return -1;
    }

    current_time = time(0);
    printf("pid: %u, start time: %s", pid, ctime(&current_time));

	reg(pid, per, PROC_TIME); //Proc filesystem

    if (check_status(pid)) {
		return -1; //Proc filesystem: Verify the process was admitted
	}

    gettimeofday(&t0, NULL);

    yield(pid); //Proc filesystem

    // real-time loop
    for(i = 0; i < 5; i++) {
		gettimeofday(&t1, NULL);
        wakeup_time = t1.tv_usec/1000 + t1.tv_sec * 1000;
		printf("pid: %u, wake-up time: %ld ms\n", pid, wakeup_time - (t0.tv_usec/1000 + t0.tv_sec * 1000));
		ret = do_job();
		gettimeofday(&t0, NULL);
        job_process_time = t0.tv_usec/1000 + t0.tv_sec*1000 - wakeup_time;
        printf ( "pid: %u, proc time: %ld ms, result: %d\n", pid, job_process_time, ret);
		yield(pid);
	}
    unreg(pid);

	current_time =time(0);
	printf("pid: %u, end time: %s", pid, ctime(&current_time));
	return 0;
}
