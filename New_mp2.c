//new mp2.c
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




//MP2 struct (Process control block)
typedef struct mp2_struct
{
  struct task_struct* task_;
  struct timer_list timer_list_;
  unsigned int state;
  unsigned long period;
  unsigned long proc_time;
  struct list_head p_list;
  //truct timespec * ts;
  struct timeval* start_time;//start time of program
  unsigned long runtime;
  pid_t pid;

}mp2_t;




//--------------------------------------------------------------------------------------------------------------------------------
//GLOBAL VARS

static mp2_t * my_current_task;// the current running task
static struct mutex mp2_mutex;
static spinlock_t mp2_spinlock; //timer lock
//https://elixir.bootlin.com/linux/v4.0/source/mm/slab.h#L19
static struct kmem_cache * k_cache;  //from slab.h
static struct task_struct * dispatcher; //our thread

//proc file stuff
static struct proc_dir_entry *proc_dir_mp2, *proc_dir_status ;
static struct workqueue_struct *_workqueue;
static int lock=0 ;

LIST_HEAD(process_list);





/*
* Removes node during distruction and once process is done executing
* used during exit and destruct
*/
static int remove_node_from_list(struct list_head* node)
{

  mp2_t * container;
  //using mutex for critical code
  if(list_empty(&process_list))
    return 0;
  mutex_lock(&mp2_mutex);
  container = list_entry(node, mp2_t, p_list);
  if(container == NULL)
  {	
  	mutex_unlock(&mp2_mutex);
    return 0;
  }

  if (my_current_task->pid == container->pid)
    my_current_task =NULL;


  list_del(node);
  del_timer(&(container->timer_list_));
  kmem_cache_free(k_cache, container);
  mutex_unlock(&mp2_mutex);

  return 0;
}

/*
* Admission control as specified in documentation
* returns pid through argument
* ratio muct be lkess then 0.693
*/
static int admission_control(char * input, pid_t * pid_)
{
  unsigned long period_;
  unsigned long p_time;
  mp2_t * tmp;
  struct list_head * temp_list;
  unsigned long ratio;// long to avoid floating points
  char c;

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
    ratio += ( (tmp->proc_time*1000)/tmp->period );
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

/*
* wake up timer function handler
*/
void timer_handler(unsigned long in)
{
  unsigned long lock_flags;
  mp2_t * curr= (mp2_t* ) in;

  spin_lock_irqsave(&mp2_spinlock, lock_flags);
  if(curr != my_current_task)
  {
    curr->state = READY;
  }
  spin_unlock_irqrestore(&mp2_spinlock, lock_flags);
  wake_up_process(dispatcher);
}






//REGISTRATION
static void init_node(mp2_t* new_task, char* buf)
{
    struct timer_list *curr_timer;

    // set up member variables
    extract_data(buf, &(new_task->pid), &(new_task->period), &(new_task->proc_time));

	new_task -> state = SLEEPING;
    new_task -> task_ = find_task_by_pid(new_task->pid);
    new_task -> start_time = (struct timeval*)kmalloc(sizeof(struct timeval), GFP_KERNEL);
    do_gettimeofday(new_task->start_time);

    // create task wakeup timer
    curr_timer = &(new_task->timer_list_);
    init_timer(curr_timer);
    curr_timer->data = (unsigned long)new_task;
    curr_timer->function = timer_handler;
}

static int add_to_list(char *buf)
{
	struct list_head * pos;
	mp2_t *entry;
	mp2_t *new_task = kmem_cache_alloc(k_cache, GFP_KERNEL);

	init_node(new_task, buf);

	mutex_lock(&mp2_mutex);
    list_for_each(pos, &process_list) {
        entry = list_entry(pos, mp2_t, p_list);
        if (entry->period > new_task->period) {
		    list_add_tail(&(new_task->p_list), pos);
			mutex_unlock(&mp2_mutex);
			return -1;
        }
    }
	list_add_tail(&(new_task->p_list), &process_list);
	mutex_unlock(&mp2_mutex);
	return -1;
}

//Yeid

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


static void yeild(char *pid)
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
	mod_timer(&(yield_task->timer_list_), jiffies + msecs_to_jiffies(yield_task->period - actual_proc_time));
	set_task_state(yield_task->task_, TASK_UNINTERRUPTIBLE);
	my_current_task = NULL;
	wake_up_process(dispatcher);

	set_current_state(TASK_UNINTERRUPTIBLE);
	schedule();
}



//-------------------------------------------------------------------------------------
//DISPATCHING THREAD
/*
* picks task to be scheduled for execution
*/
static void schedule_next_task(void)
{

  mp2_t *running_task;
  mp2_t *next_task;
  struct sched_param sparam;

  struct list_head* iter;
  mp2_t *tmp;
  printk(KERN_ALERT "SCHEDULAR HELPER STARTING");
  running_task= my_current_task;
  if(my_current_task)
  {
    list_for_each(iter, &process_list)
    {
      tmp = list_entry(iter, mp2_t, p_list);
      if(tmp != NULL && tmp->state == READY)
      {
        next_task = tmp;
        break;
      }
    }
    if(running_task-> state== RUNNING)
      running_task->state= READY;
    sparam.sched_priority=0;
    sched_setscheduler(running_task ->task_, SCHED_NORMAL, &sparam);
    if(next_task && next_task->state==READY)
    {
      printk(KERN_ALERT "starting (switching bterween tasks)%u -> %u", my_current_task->pid, next_task->pid);
      sparam.sched_priority = MAX_PRIORITY;
      //check order
      sched_setscheduler(next_task->task_, SCHED_FIFO ,&sparam);
      do_gettimeofday(next_task->start_time);
      wake_up_process(next_task->task_);
      my_current_task = next_task;
      my_current_task->state = RUNNING;
    }
    return;
  }
  if(list_empty(&process_list))
    return;
  list_for_each(iter, &process_list)
  {
      tmp = list_entry(iter, mp2_t, p_list);
      if(tmp != NULL && tmp->state == READY)
      {
        next_task = tmp;
        break;
      }
  }
  if(next_task && next_task->state==READY)
  {
    printk(KERN_ALERT "starting %u", next_task->pid);
    sparam.sched_priority = MAX_PRIORITY;
    //check order
    sched_setscheduler(next_task->task_, SCHED_FIFO ,&sparam);
    do_gettimeofday(next_task->start_time);
    wake_up_process(next_task->task_);
    my_current_task = next_task;
    my_current_task->state = RUNNING;
  }

}
/*
* dispatcher function controls the schdeuling
* runns the dispatching thread
*/
static int scheduler_dispatch (void * data)
{
  while(1)
  {
    if (kthread_should_stop())
      return 0;
    printk("DISPATCHING THREAD STARTING");
    mutex_lock(&mp2_mutex);
    schedule_next_task();
    mutex_unlock(&mp2_mutex);
    set_current_state(TASK_UNINTERRUPTIBLE); //might be in yeild
    schedule();
    printk(KERN_ALERT "PID %d being scheduled", my_current_task->pid);
  }

  printk(KERN_ALERT "KTHREAD FINISHED");
  return 0;

}









//FILE OPS
//-----------------------------------------------------------------------
//File struct, read and write
/*
* File read function
* bux fixed from MP1
*/
static ssize_t pfile_read(struct file *file, char __user * buf, size_t count, loff_t * data)
{
  //locals need to be declared before anything
  size_t ret_val=0;
  int ctr, length;
  char * read_buffer =NULL;
  char read [256];// might need to be 128
  //struct list_head * temp;
  mp2_t * container; //mistake from MP1

  ctr = length = 0;
  //kmalloc for k heap
  read_buffer =(char *)( kmalloc(2048, GFP_KERNEL));

  mutex_lock(&mp2_mutex);
  list_for_each_entry(container, &process_list, p_list)
  {
     memset(read, 0, 256);//resets read array
     length= sprintf(read, "%u, %lu, %lu\n", container->pid, container->period, container->proc_time );
     ctr += length;
     strcat(read_buffer, read);
  }
  mutex_unlock(&mp2_mutex);
  if (*data >0 ) return 0;
  copy_to_user(buf, read_buffer,ctr);

  kfree(read_buffer);
  *data += ctr;
  ret_val = ctr;
  return ret_val;
}


/*
* Write function
*/
static ssize_t pfile_write(struct file *file,const  char __user *buffer, size_t count, loff_t * data)
{

    //unsigned long curr_pid ;
    int ret_val;
    char * t_buffer;
    char cmd;
    pid_t _pid_;
    struct list_head * read;

    printk(KERN_ALERT "WRITE FUNCTION REACHED");
    t_buffer = (char *)kmalloc(256, GFP_KERNEL);
    lock=1;
    ret_val =-1;
    copy_from_user(t_buffer, buffer, count);
    //printk(KERN_ALERT "WRITE FUNCTION REACHED");
    t_buffer [count]= '\0';
    cmd = t_buffer[0];

    if(admission_control(t_buffer, &_pid_)==0)
    {
      ret_val=0;
      goto done_write;
    }

    printk(KERN_ALERT "COMMAND %c", cmd);

    if(cmd== 'R')
    {
      //register
      add_to_list(t_buffer);
      printk(KERN_ALERT "PID %u REGISTERED", _pid_);
    }
    else if(cmd =='Y')
    {
      //yeild
      printk(KERN_ALERT "starting %u YEILD", _pid_);
      yeild(t_buffer +2);
      printk(KERN_ALERT "PID %u YEILD", _pid_);
    }
    else if(cmd =='D')
    {
      //de register
      get_process_node( _pid_ , read);
      remove_node_from_list(read);
      printk(KERN_ALERT "DEREGITER: %u", _pid_);
    }
    else
      ret_val=0;

    done_write:
    kfree(t_buffer);
    if(ret_val ==-1)
      *data = -1;

    lock=0;
    return ret_val;

}

static const struct file_operations mp2_file_ops = {
   .owner = THIS_MODULE,
   .read = pfile_read,
   .write = pfile_write,

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

   _workqueue = create_workqueue("mp2");

   spin_lock_init(&mp2_spinlock);
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
  spin_lock(&mp2_spinlock);
  //when making list_head, use that name
  
  list_for_each_safe(temp1, temp2, &process_list){
    remove_node_from_list(temp1);
   }
   //spin_unlock(&mp2_spinlock);
   //mutex_unlock(&mp2_mutex);
   
   remove_proc_entry("status", proc_dir_mp2);
   remove_proc_entry("mp2", NULL);


   kthread_stop(dispatcher );//check
   kmem_cache_destroy(k_cache);

   mutex_destroy(&mp2_mutex);
  //spin_lock_destroy(&mp2_spinlock);
   printk(KERN_ALERT "MP2 MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(mp2_init);
module_exit(mp2_exit);
