 #define LINUX

#include "mp2_given.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lall3");
MODULE_DESCRIPTION("CS-423 MP2");

#define DEBUG 1
#define FILENAME "status"
#define DIRECTORY "mp2"
#define MAX_BUF_SIZE 128
#define SLEEPING 0
#define READY 1
#define RUNNING 2


//MP2 struct
typedef struct mp2_struct
{
  struct task_struct* task_;
  struct timer_list timer_;
  unsigned int state;
  unsigned long period;
  unsigned long proc_time;
  struct list_head p_list;
  //truct timespec * ts;
  struct timeval* start_time;//start time of program
  unsigned long runtime;
  pid_t pid;

}mp2_t;

static struct proc_dir_entry *proc_dir_mp2;
static struct proc_dir_entry *proc_dir_status;
static struct mutex mp2_mutex;
static struct kmem_cache *k_cache;
static mp2_t *my_current_task;
static struct task_struct *dispatcher;
static spinlock_t mp2_lock;

LIST_HEAD(process_list);


/*
* Helper function to parse the input, extracts pid, proc_time, and period
*/
static void extract_data(char * input, pid_t * pid, unsigned long * a, unsigned long * b)
{
  //make sure this works
  char c;
  sscanf(input, "%c, %d, %lu, %lu", &c, pid, a, b);
  printk (KERN_ALERT "OG MGS %s", input);

}

/*
* returns pointer to node of given pid as param
*/
static void get_process_node(pid_t pid_,  struct list_head * ret)
{
    struct list_head * temp1, *temp2;
    mp2_t * curr;
    //ret=NULL;
    mutex_lock(&mp2_mutex);
    list_for_each_safe(temp1, temp2, &process_list)
    {
      curr=list_entry(temp1 , mp2_t , p_list);
      if(pid_ == curr->pid)
      {
        ret = temp1;
        break;
      }
    }
    mutex_unlock(&mp2_mutex);
}

// Called when user application use "cat" or "fopen"
// The function read the status file and print the information related out
static ssize_t pfile_read(struct file *file, char __user * buffer, size_t count, loff_t * data)
{
  

   size_t copied = 0;
    char * buf = NULL;
    struct list_head *pos = NULL;
    mp2_t *tmp = NULL;
    char currData[MAX_BUF_SIZE];
    int currByte;
    buf = (char*) kmalloc(1024, GFP_KERNEL);

    // read each node on the list and print the information as [pid: period, proc_time] to user
  mutex_lock(&mp2_mutex);
    list_for_each(pos, &process_list) {
        tmp = list_entry(pos, mp2_t, p_list);
        memset(currData, 0, MAX_BUF_SIZE);
        currByte = sprintf(currData, "%u, %lu, %lu\n", tmp->pid, tmp->period, tmp->proc_time);
        strcat(buf, currData);
        copied += currByte;
    }
    mutex_unlock(&mp2_mutex);

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
  mp2_t *entry;
  mp2_t *prev_task;
  struct sched_param new_sparam;
  struct sched_param old_sparam;
  struct list_head *pos;
  mp2_t *next_task=NULL;

  printk(KERN_ALERT "START TO PICK NEXT TASK");

  if(my_current_task)
  {
    list_for_each(pos, &process_list) {
      entry = list_entry(pos, mp2_t, p_list);
      if (entry->state == READY) {
        next_task = entry;
        break;
      }
    }

    prev_task = my_current_task;
    if(prev_task->state == RUNNING)
    {
      prev_task->state = READY;
    }

    //old task
    old_sparam.sched_priority=0;
    sched_setscheduler(prev_task->task_, SCHED_NORMAL, &old_sparam);

    if(next_task && next_task->state==READY)
    {
      // new task
      printk(KERN_ALERT "PROCESS %u START TO RUN", next_task->pid);
      wake_up_process(next_task->task_);
      new_sparam.sched_priority=MAX_USER_RT_PRIO-1;
      sched_setscheduler(next_task->task_, SCHED_FIFO, &new_sparam);
      do_gettimeofday(next_task->start_time);
      my_current_task = next_task;
      my_current_task->state = RUNNING;
    }
  }
  else
  {
    if(list_empty(&process_list))
    {
      return;
    }
    list_for_each(pos, &process_list) {
      entry = list_entry(pos, mp2_t, p_list);
      if (entry->state == READY) {
        next_task = entry;
        break;
      }
    }
    if(next_task && next_task->state==READY)
    {
      new_sparam.sched_priority=MAX_USER_RT_PRIO-1;
      sched_setscheduler(next_task->task_, SCHED_FIFO, &new_sparam);
      do_gettimeofday(next_task->start_time);
      wake_up_process(next_task->task_);
      my_current_task = next_task;
      my_current_task->state = RUNNING;
    }
    }
}

// Called when one of the tasks is waked up
// The function checks if a context switch is needed and do the context switch
static int scheduler_dispatch(void *data)
{
  while(1)
  {
    if(kthread_should_stop())
    {
      printk(KERN_ALERT "KTHREAD FINISH ITS JOB AND SHOULD STOP");
      return 0;
    }
    printk(KERN_ALERT "DISPATCHING THREAD STARTS WORKING");
    mutex_lock(&mp2_mutex);
    pick_task_to_run();
    mutex_unlock(&mp2_mutex);
    set_current_state(TASK_UNINTERRUPTIBLE);
    schedule();
  }
  return 0;
}

/*
* wake up timer function handler
*/
void timer_handler(unsigned long in)
{
  unsigned long lock_flags;
  mp2_t * curr= (mp2_t* ) in;

  spin_lock_irqsave(&mp2_lock, lock_flags);
  if(curr != my_current_task)
  {
    curr->state = READY;
  }
  spin_unlock_irqrestore(&mp2_lock, lock_flags);
  wake_up_process(dispatcher);
}


// Helper function for parsing pid, period and process time
// We store the parsed information in the call-by-reference parameters
void _read_process_info(char *info, pid_t *pid, unsigned long *period, unsigned long *proc_time)
{
    int i = 0;
    char *pch;
    char *dataHolder = (char*)kmalloc(strlen(info)+1, GFP_KERNEL);
    char *start_pos = dataHolder;
  if(dataHolder)
    {
        strcpy(dataHolder, info);
    }

    pch = strsep(&dataHolder, " ");

    // parse user input and store it into the node
    for(i = 0; i < 3 && pch!=NULL; i ++)
    {
        if(i==0)
        {
            sscanf(pch, "%u", pid);
        }
        else if(i==1)
        {
            sscanf(pch, "%lu", period);
        }
        else
        {
            sscanf(pch, "%lu", proc_time);
        }
    //kfree(pch);
        pch = strsep(&dataHolder, " ,");
    }
  kfree(start_pos);
}


// Called when a new self-defined task node is allocated
// Store user input, set task state and create timer for it
static void init_node(mp2_t* new_task, char* buf)
{
    struct timer_list *curr_timer;

    // set up member variables
    _read_process_info(buf, &(new_task->pid), &(new_task->period), &(new_task->proc_time));
  new_task -> state = SLEEPING;
    new_task -> task_ = find_task_by_pid(new_task->pid);
    new_task -> start_time = (struct timeval*)kmalloc(sizeof(struct timeval), GFP_KERNEL);
    do_gettimeofday(new_task->start_time);

    // create task wakeup timer
    curr_timer = &(new_task->timer_);
    init_timer(curr_timer);
    curr_timer->data = (unsigned long)new_task;
    curr_timer->function = timer_handler;
}

// Add a newly created task node into the existing task linked list
// Ordered bt task period (shortest period first)
static int add_to_list(char *buf)
{
  struct list_head *pos;
  mp2_t *entry;
  mp2_t *new_task = kmem_cache_alloc(k_cache, GFP_KERNEL);

  init_node(new_task, buf);

  mutex_lock(&mp2_mutex);
    list_for_each(pos, &process_list) {
        entry = list_entry(pos, mp2_t, p_list);
        if (entry->period > new_task->period) {
        list_add_tail(&new_task->p_list, pos);
      mutex_unlock(&mp2_mutex);
      return -1;
        }
    }
  list_add_tail(&(new_task->p_list), &process_list);
  mutex_unlock(&mp2_mutex);
  return -1;
}


/*
* Regsiter function. Adds task to list.
* param : buffer copied from user
*/
static void register_helper(char * input)
{
  
  struct list_head * t;
  mp2_t * curr;
  mp2_t * new_task = kmem_cache_alloc(k_cache, GFP_KERNEL );
  struct timer_list * t_timer;
  extract_data(input, &(new_task->pid), &(new_task->period), &(new_task->proc_time));
  printk (KERN_ALERT "REGISTERING %u, %lu, %lu", (new_task->pid), (new_task->period), (new_task->proc_time) );
  new_task->state = SLEEPING; //changed
  //get_process_node(new_task->pid, (struct list_head *)&(new_task->task_));
  

  new_task->task_ = find_task_by_pid(new_task->pid);
  new_task->start_time = (struct timeval*)( kmalloc(sizeof(struct timeval),GFP_KERNEL) );
  do_gettimeofday(new_task->start_time);
  init_timer(&(new_task->timer_));
  t_timer = &(new_task->timer_);
  t_timer->data = (unsigned long)new_task;
  t_timer->function = timer_handler;

  mutex_lock(&mp2_mutex);
  list_for_each(t ,&process_list){
    curr= list_entry(t, mp2_t, p_list);
    if(curr->period > new_task->period)
    {
      list_add_tail(&(new_task->p_list), t);
      mutex_unlock(&mp2_mutex);
      return;
    }
  }
  list_add_tail(&(new_task->p_list), &process_list);
  mutex_unlock(&mp2_mutex);

}





// Free a allocated task node, remove it from the list
static void remove_node_from_list(struct list_head *pos)
{
  mp2_t *entry;

  mutex_lock(&mp2_mutex);
  entry = list_entry(pos, mp2_t, p_list);
  printk(KERN_ALERT "START DESTRUCT TASK: %u",entry->pid);

    // if the current running task would like to unregister itself,
    // set my_current_task to NULL
  if(my_current_task && entry->pid == my_current_task->pid)
  {
    my_current_task = NULL;
  }
  list_del(pos);
  del_timer(&(entry->timer_));
  kmem_cache_free(k_cache, entry);
  mutex_unlock(&mp2_mutex);
}

// Helper function that traverse the entire task linked list and
// find a task according to its pid
static struct list_head *find_task_node_by_pid(char *pid)
{
    struct list_head *pos;
    struct list_head *next;
    mp2_t *curr;
    char curr_pid[20];

    mutex_lock(&mp2_mutex);

    list_for_each_safe(pos, next, &process_list){
        curr = list_entry(pos, mp2_t, p_list);
        memset(curr_pid, 0, 20);
        sprintf(curr_pid, "%u", curr->pid);
        if(strcmp(curr_pid, pid)==0)
        {
            mutex_unlock(&mp2_mutex);
            return pos;
        }
    }

    mutex_unlock(&mp2_mutex);
    return NULL;
}

// Called when user input "Y" as command
// Put yield task into sleeping state and start its wakeup timer
static int _yield_handler(char *pid)
{
  mp2_t *yield_task;
    struct list_head *yield_pos;
  struct timeval curr_time;
  unsigned long actual_proc_time;
  yield_pos = find_task_node_by_pid(pid);
    yield_task = list_entry(yield_pos, mp2_t, p_list);

  yield_task->state = SLEEPING;
  do_gettimeofday(&curr_time);
  actual_proc_time = (curr_time.tv_sec*1000 - yield_task->start_time->tv_sec*1000) + (curr_time.tv_usec/1000 - yield_task->start_time->tv_usec /1000);
  mod_timer(&(yield_task->timer_), jiffies + msecs_to_jiffies(yield_task->period - actual_proc_time));
  set_task_state(yield_task->task_, TASK_UNINTERRUPTIBLE);
  my_current_task = NULL;
  wake_up_process(dispatcher);

  set_current_state(TASK_UNINTERRUPTIBLE);
  schedule();

  return 0;
}

// Called when a new task incoming
// Check if the new task and the existing tasks could be scheduled without
// missing deadlines according to thir process time and period
static int admission_control(char * input)
{
  unsigned long period_;
  unsigned long p_time;
  mp2_t * tmp;
  struct list_head * temp_list;
  unsigned long ratio;
  char c;
  pid_t * pid_ =kmalloc(sizeof(pid_t), GFP_KERNEL);

  if( input [0]== 'R')
  {
    extract_data(input, pid_ , &period_ , &p_time);
    printk (KERN_ALERT "New  %d, %lu, %lu", *pid_, period_, p_time);
    ratio = (p_time*1000)/(period_);
  }
  else
  {
    sscanf(input, "%c, %d", &c, pid_);
    printk (KERN_ALERT "REQUESTED  %c", c);
    return 1;
  }
  mutex_lock(&mp2_mutex);
  list_for_each(temp_list, &process_list)
  {
    tmp = list_entry(temp_list, mp2_t, p_list);
    ratio += ((unsigned int)(tmp->proc_time*1000/tmp->period));
  }

  mutex_unlock(&mp2_mutex);
  if(ratio < 694)
  {
      printk(KERN_ALERT "Admission Passed");
      return 1;
  }
  printk(KERN_ALERT "Admission failed ");
  return 0;

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
    register_helper(buf);
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
        remove_node_from_list(pos);
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

static const struct file_operations mp2_file_ops = {
    .owner = THIS_MODULE,
    .read = pfile_read,
    .write = mp2_write,
};


/*
* mp2_init - Called when module is loaded
*/
int __init mp2_init(void)
{
   #ifdef DEBUG
   printk(KERN_ALERT "MP2 MODULE LOADING\n");
   #endif

   //proc setup
   proc_dir_mp2 = proc_mkdir( "mp2" ,NULL);
   proc_dir_status = proc_create("status", 0666, proc_dir_mp2, &mp2_file_ops);

   //initializing globals
   my_current_task = NULL;

   //add function name
   dispatcher = kthread_create( scheduler_dispatch , NULL , "mp2");
   //slab accolator, edit this with proper arguments
   k_cache= kmem_cache_create("k_cache", sizeof(mp2_t) , 0, SLAB_HWCACHE_ALIGN, NULL);

   //_workqueue = create_workqueue("mp2");

   spin_lock_init(&mp2_lock);
   mutex_init(&mp2_mutex);

   printk(KERN_ALERT "MP2 MODULE LOADED\n");
   return 0;
}



/*
* mp2_exit - Called when module is unloaded
*
*/
void __exit mp2_exit(void)
{
   struct list_head *temp1, *temp2;
   #ifdef DEBUG
   printk(KERN_ALERT "MP2 MODULE UNLOADING\n");
   #endif
   //mutex_lock(&mp2_mutex);

//mem leak_________________FIX!!!!!!!!!!
  spin_lock(&mp2_lock);
  //when making list_head, use that name
  
  list_for_each_safe(temp1, temp2, &process_list){
    remove_node_from_list(temp1);
   }
   //spin_unlock(&mp2_lock);
   //mutex_unlock(&mp2_mutex);
   
   remove_proc_entry("status", proc_dir_mp2);
   remove_proc_entry("mp2", NULL);


   kthread_stop(dispatcher );//check
   kmem_cache_destroy(k_cache);

   mutex_destroy(&mp2_mutex);
  //spin_lock_destroy(&mp2_lock);
   printk(KERN_ALERT "MP2 MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(mp2_init);
module_exit(mp2_exit);
