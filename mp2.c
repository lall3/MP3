
#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include "mp2_given.h"

//added inclusions
#include <linux/timer.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/gfp.h> // flags
#include <linux/jiffies.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/workqueue.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/spinlock_types.h>

//defining constants
#define SLEEPING  0
#define READY     1
#define RUNNING   2
//https://stackoverflow.com/questions/8887531/which-real-time-priority-is-the-highest-priority-in-linux
//varify this
#define MAX_PRIORITY 99

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lall3");
MODULE_DESCRIPTION("CS-423 MP2");

#define DEBUG 1
#define FILENAME "status"
#define DIRECTORY "mp2"
#define MAX_BUF_SIZE 128
#define SLEEPING_STATE 0
#define READY_STATE 1
#define RUNNING_STATE 2

// A self-defined structure represents PCB
// Index by pid, used as a node in the task linked list
typedef struct mp2_task_struct {
	struct task_struct* linux_task;
	struct timer_list wakeup_timer;
	pid_t pid;
	int state;
	unsigned long proc_time;
	unsigned long period;
	struct list_head process_node;
	struct timeval *start_time;
} task_node_t;

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_entry;
static struct mutex my_mutex;
static struct kmem_cache *task_cache;
static task_node_t *current_running_task;
static struct task_struct *dispatching_task;
static spinlock_t timer_lock;

LIST_HEAD(taskList);

// Called when user application use "cat" or "fopen"
// The function read the status file and print the information related out
static ssize_t mp2_read(struct file *file, char __user * buffer, size_t count, loff_t * data)
{
    size_t copied = 0;
    char * buf = NULL;
    struct list_head *pos = NULL;
    task_node_t *tmp = NULL;
    char currData[MAX_BUF_SIZE];
    int currByte;
    buf = (char*) kmalloc(1024, GFP_KERNEL);

    // read each node on the list and print the information as [pid: period, proc_time] to user
	mutex_lock(&my_mutex);
    list_for_each(pos, &taskList) {
        tmp = list_entry(pos, task_node_t, process_node);
        memset(currData, 0, MAX_BUF_SIZE);
        currByte = sprintf(currData, "%u: %lu, %lu\n", tmp->pid, tmp->period, tmp->proc_time);
        strcat(buf, currData);
        copied += currByte;
    }
    mutex_unlock(&my_mutex);

    if(*data>0)
    {
        return 0;
    }
    copy_to_user(buffer, buf, copied);
    kfree(buf);
    *data += copied;

    return copied;

}

// Helper function for dispatching thread to pick the next running task
// We will pick the ready task with highest priority
static void pick_task_to_run(void)
{
	task_node_t *entry;
	task_node_t *prev_task;
	struct sched_param new_sparam;
	struct sched_param old_sparam;
	struct list_head *pos;
	task_node_t *next_task=NULL;

	printk(KERN_ALERT "START TO PICK NEXT TASK");

	if(current_running_task)
	{
		list_for_each(pos, &taskList) {
			entry = list_entry(pos, task_node_t, process_node);
			if (entry->state == READY_STATE) {
				next_task = entry;
				break;
			}
		}

		prev_task = current_running_task;
		if(prev_task->state == RUNNING_STATE)
		{
			prev_task->state = READY_STATE;
		}

		//old task
		old_sparam.sched_priority=0;
		sched_setscheduler(prev_task->linux_task, SCHED_NORMAL, &old_sparam);

		if(next_task && next_task->state==READY_STATE)
		{
			// new task
			printk(KERN_ALERT "PROCESS %u START TO RUN", next_task->pid);
			wake_up_process(next_task->linux_task);
			new_sparam.sched_priority=MAX_USER_RT_PRIO-1;
			sched_setscheduler(next_task->linux_task, SCHED_FIFO, &new_sparam);
			do_gettimeofday(next_task->start_time);
			current_running_task = next_task;
			current_running_task->state = RUNNING_STATE;
		}
	}
	else
	{
		if(list_empty(&taskList))
		{
			return;
		}
		list_for_each(pos, &taskList) {
			entry = list_entry(pos, task_node_t, process_node);
			if (entry->state == READY_STATE) {
				next_task = entry;
				break;
			}
		}
		if(next_task && next_task->state==READY_STATE)
		{
			new_sparam.sched_priority=MAX_USER_RT_PRIO-1;
			sched_setscheduler(next_task->linux_task, SCHED_FIFO, &new_sparam);
			do_gettimeofday(next_task->start_time);
			wake_up_process(next_task->linux_task);
			current_running_task = next_task;
			current_running_task->state = RUNNING_STATE;
		}
    }
}

// Called when one of the tasks is waked up
// The function checks if a context switch is needed and do the context switch
static int dispatching_thread(void *data)
{
	while(1)
	{
		if(kthread_should_stop())
		{
			printk(KERN_ALERT "KTHREAD FINISH ITS JOB AND SHOULD STOP");
			return 0;
		}
		printk(KERN_ALERT "DISPATCHING THREAD STARTS WORKING");
		mutex_lock(&my_mutex);
		pick_task_to_run();
		mutex_unlock(&my_mutex);
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule();
	}
	return 0;
}

// Called when one of the task's timer is expired
// Set the task to ready state and call the dispatching thread
void wakeup_timer_handler(unsigned long arg)
{
	unsigned long flags;
	task_node_t *curr_node;
	curr_node = (task_node_t *)arg;
	spin_lock_irqsave(&timer_lock, flags);
	if (curr_node != current_running_task) {
		curr_node -> state = READY_STATE;
	}
	printk(KERN_ALERT "PROCESS %u IS WAKE UP, READY NOW", curr_node->pid);
	spin_unlock_irqrestore(&timer_lock, flags);
	wake_up_process(dispatching_task);
}

// Helper function for parsing pid, period and process time
// We store the parsed information in the call-by-reference parameters
void _read_process_info(char *info, pid_t *pid, unsigned long *period, unsigned long *proc_time)
{
  char c;
  sscanf(input, "%c, %d, %lu, %lu", &c, pid, period, proc_time);
  }


// Called when a new self-defined task node is allocated
// Store user input, set task state and create timer for it
static void init_node(task_node_t* new_task, char* buf)
{
    struct timer_list *curr_timer;

    // set up member variables
    _read_process_info(buf, &(new_task->pid), &(new_task->period), &(new_task->proc_time));
	new_task -> state = SLEEPING_STATE;
    new_task -> linux_task = find_task_by_pid(new_task->pid);
    new_task -> start_time = (struct timeval*)kmalloc(sizeof(struct timeval), GFP_KERNEL);
    do_gettimeofday(new_task->start_time);

    // create task wakeup timer
    curr_timer = &(new_task->wakeup_timer);
    init_timer(curr_timer);
    curr_timer->data = (unsigned long)new_task;
    curr_timer->function = wakeup_timer_handler;
}

// Add a newly created task node into the existing task linked list
// Ordered bt task period (shortest period first)
static int add_to_list(char *buf)
{
	struct list_head *pos;
	task_node_t *entry;
	task_node_t *new_task = kmem_cache_alloc(task_cache, GFP_KERNEL);

	init_node(new_task, buf);

	mutex_lock(&my_mutex);
    list_for_each(pos, &taskList) {
        entry = list_entry(pos, task_node_t, process_node);
        if (entry->period > new_task->period) {
		    list_add_tail(&new_task->process_node, pos);
			mutex_unlock(&my_mutex);
			return -1;
        }
    }
	list_add_tail(&(new_task->process_node), &taskList);
	mutex_unlock(&my_mutex);
	return -1;
}

// Free a allocated task node, remove it from the list
static void destruct_node(struct list_head *pos)
{
	task_node_t *entry;

	mutex_lock(&my_mutex);
	entry = list_entry(pos, task_node_t, process_node);
	printk(KERN_ALERT "START DESTRUCT TASK: %u",entry->pid);

    // if the current running task would like to unregister itself,
    // set current_running_task to NULL
	if(current_running_task && entry->pid == current_running_task->pid)
	{
		current_running_task = NULL;
	}
	list_del(pos);
	del_timer(&(entry->wakeup_timer));
	kmem_cache_free(task_cache, entry);
	mutex_unlock(&my_mutex);
}

// Helper function that traverse the entire task linked list and
// find a task according to its pid
static struct list_head *find_task_node_by_pid(char *pid)
{
    struct list_head *pos;
    struct list_head *next;
    task_node_t *curr;
    char curr_pid[20];

    mutex_lock(&my_mutex);

    list_for_each_safe(pos, next, &taskList){
        curr = list_entry(pos, task_node_t, process_node);
        memset(curr_pid, 0, 20);
        sprintf(curr_pid, "%u", curr->pid);
        if(strcmp(curr_pid, pid)==0)
        {
            mutex_unlock(&my_mutex);
            return pos;
        }
    }

    mutex_unlock(&my_mutex);
    return NULL;
}

// Called when user input "Y" as command
// Put yield task into sleeping state and start its wakeup timer
static int _yield_handler(char *pid)
{
	task_node_t *yield_task;
    struct list_head *yield_pos;
	struct timeval curr_time;
	unsigned long actual_proc_time;
	yield_pos = find_task_node_by_pid(pid);
    yield_task = list_entry(yield_pos, task_node_t, process_node);

	yield_task->state = SLEEPING_STATE;
	do_gettimeofday(&curr_time);
	actual_proc_time = (curr_time.tv_sec*1000 - yield_task->start_time->tv_sec*1000) + (curr_time.tv_usec/1000 - yield_task->start_time->tv_usec /1000);
	mod_timer(&(yield_task->wakeup_timer), jiffies + msecs_to_jiffies(yield_task->period - actual_proc_time));
	set_task_state(yield_task->linux_task, TASK_UNINTERRUPTIBLE);
	current_running_task = NULL;
	wake_up_process(dispatching_task);

	set_current_state(TASK_UNINTERRUPTIBLE);
	schedule();

	return 0;
}

// Called when a new task incoming
// Check if the new task and the existing tasks could be scheduled without
// missing deadlines according to thir process time and period
static bool admission_control(char *buf)
{
    struct list_head *pos;
    task_node_t *entry;
    pid_t curr_pid;
    unsigned long curr_period;
    unsigned long curr_proc_time;
    int fixed_proc_time;
    int fixed_period;
    int ratio = 0;

    _read_process_info(buf, &curr_pid, &curr_period, &curr_proc_time);
    ratio+=(int)curr_proc_time*1000/((int)curr_period);

	mutex_lock(&my_mutex);
    list_for_each(pos, &taskList) {
        entry = list_entry(pos, task_node_t, process_node);
        fixed_proc_time = (int)entry->proc_time*1000;
        fixed_period = (int)entry->period;
        ratio += fixed_proc_time/fixed_period;

    }
	mutex_unlock(&my_mutex);
    if(ratio <= 693)
    {
        printk(KERN_ALERT "Process %u pass the admission control", curr_pid);
        return true;
    }
    else
    {
        printk(KERN_ALERT "Process %u did not pass the admission control", curr_pid);
        return false;
    }
}

// Called when user application registered a process
// The function get the pid from the user and put it on the linked list, which actually write it in the status file
static ssize_t mp2_write(struct file *file, const char __user *buffer, size_t count, loff_t * data){
	char * buf = (char*)kmalloc(count+1, GFP_KERNEL);
	int ret = -1;
    struct list_head *pos;

	if (count > MAX_BUF_SIZE - 1) {
		count = MAX_BUF_SIZE - 1;
	}

	copy_from_user(buf, buffer, count);
	buf[count] = '\0';

    if(!admission_control(buf))
    {
        return 0;
    }

	printk(KERN_ALERT "MP2_WRITE CALLED, INPUT:%s\n", buf);

	// Check the starting char of buf, if:
	// 1.register: R,PID,PERIOD,COMPUTATION
	if (buf[0] == 'R') {
		ret = add_to_list(buf+2);
		printk(KERN_ALERT "REGISTERED PID:%s", buf+2);
	}
	else if (buf[0] == 'Y') {
	// 2.yield: Y,PID
		printk(KERN_ALERT "YIELD PID:%s", buf+2);
		_yield_handler(buf+2);
	}
	else if (buf[0] == 'D') {
	// 3.unregister: D,PID
        pos = find_task_node_by_pid(buf+2);
        destruct_node(pos);
        ret = -1;
		printk(KERN_ALERT "UNREGISTERED PID: %s", buf+2);
	}
	else {
		kfree(buf);
		return 0;
	}
	kfree(buf);
	return ret;
}

static const struct file_operations mp2_file = {
    .owner = THIS_MODULE,
    .read = mp2_read,
    .write = mp2_write,
};

// mp2_init - Called when module is loaded
int __init mp2_init(void)
{
    #ifdef DEBUG
    printk(KERN_ALERT "MP2 MODULE LOADING\n");
    #endif
    // create proc directory and file entry
    proc_dir = proc_mkdir(DIRECTORY, NULL);
    proc_entry = proc_create(FILENAME, 0666, proc_dir, & mp2_file);
	current_running_task = NULL;

	// init kthread, binding dispatching thread function
	dispatching_task = kthread_create(dispatching_thread, NULL, "mp2");

	// create cache for slab allocator
	task_cache = kmem_cache_create("task_cache", sizeof(task_node_t), 0, SLAB_HWCACHE_ALIGN, NULL);

    // init mutex lock
    mutex_init(&my_mutex);
   	spin_lock_init(&timer_lock);
	printk(KERN_ALERT "MP2 MODULE LOADED\n");
    return 0;
}

// mp2_exit - Called when module is unloaded
void __exit mp2_exit(void)
{
    struct list_head *pos;
    struct list_head *next;

    #ifdef DEBUG
    printk(KERN_ALERT "MP2 MODULE UNLOADING\n");
    #endif

    // remove every node on linked list and remove the list
    list_for_each_safe(pos, next, &taskList){
		destruct_node(pos);
	}

    // remove file entry and repository
    remove_proc_entry(FILENAME, proc_dir);
    remove_proc_entry(DIRECTORY, NULL);

	// stop dipatching thread
	kthread_stop(dispatching_task);

	// destroy memory cache
	kmem_cache_destroy(task_cache);

    printk(KERN_ALERT "MP2 MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(mp2_init);
module_exit(mp2_exit);
