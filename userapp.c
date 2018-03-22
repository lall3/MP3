#include "userapp.h"
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>




int factorial(void)
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


int main(int argc, char* argv[])
{
    unsigned long input = strtoul(argv[1], NULL, 10);
	pid_t pid = getpid();
    int i, ret, temp;
	time_t current_time;
    char* read_line= NULL;
    int param =0;

    FILE * proc = fopen( "/proc/mp2/status", "a+");
    if(!proc) {
        perror("file doesn't exist\n");
        return -1;
    }

    current_time = time(0);
    printf("PID: %u start time: %s", pid, ctime(&current_time));

	temp = fprintf(proc, "R, %d, %lu, d", pid, input, 50);

    factorial();

    //yeild
    temp = fprintf(proc, "Y, %d", pid);


    printf("Done yeilding \n");

    //deregister
    temp = fprintf(proc, "D, %d", pid);

	current_time = time(0);
	printf("Pid: %u end time: %s", pid, ctime(&current_time));

    proc.close();



    proc = fopen( "/proc/mp2/status", "r+");
    while ( (read = getline(&read_line, param , proc )) != -1 )
    {
        printf("%c\n", read_line);
        param++;
    }
    proc.close();


	return 0;
}
