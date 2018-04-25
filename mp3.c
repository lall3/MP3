#define LINUX

// Kernel
#include <linux/module.h>
#include <linux/kernel.h>
// Kernel Flags
#include <linux/gfp.h>
// System Calls
#include <linux/syscalls.h> 
#include <linux/fcntl.h>
// Proc filesystem
#include <linux/proc_fs.h>
// Filesystem I/O
#include <linux/fs.h>
#include <linux/file.h> 
#include <linux/buffer_head.h>
#include <asm/segment.h>
// Character Device
#include <linux/cdev.h>
// WorkQueue
#include <linux/workqueue.h>
// Memory
#include <linux/slab.h>
#include <linux/vmalloc.h>
// Spinlock
#include <linux/spinlock.h>
// User Access
#include <asm/uaccess.h>
// Timer Libraries
#include <linux/timer.h>
#include <linux/jiffies.h>
// Type Libraries
#include <linux/types.h>
// String
#include <linux/string.h>

// Given Functions
#include "mp3_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Group_ID");
MODULE_DESCRIPTION("CS-423 MP3");

// Global Constants
#define DEBUG 1
#define FILENAME "status"
#define DIRECTORY "mp3"
#define BUFSIZE 128
#define SHAREDBUFSIZE (1024*512)
#define LONGSIZE (sizeof(long))
#define PAGESIZE 4096

/**
 * MP Struct
 * Linux Kernel Linked List Struct
 *
 * list linux kernel linked list
 * linuxtask linux kernel task struct
 * pid user application pid
 * process_usage process utilization
 * maj_flt major fault count
 * min_flt minor fault count
**/
typedef struct mp_task_struct {
  struct list_head list;
  struct task_struct* linuxtask;

  unsigned int pid;
  unsigned long process_usage;
  unsigned long maj_flt;
  unsigned long min_flt; 
} mp_struct;

//Time Interval Manager
static unsigned long last_time = 0;

//Character Device Data Struct
struct cdev cdevdata;

// Virtual Buffer
static long* shared_buffer;
static int shared_index = 0;

// ProcFS Structs
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_entry;

// Linux Kernel Linked List
static mp_struct head;
static mp_struct *tmp;
static struct list_head *pos, *q;
static int list_size = 0;

// Semaphore Lock
static spinlock_t lock;

// Interrupt Variables
static struct workqueue_struct *queue;

/**
 * Get Current Time in jiffies
 *
 * RETURN current time in jiffies
**/
static unsigned long _get_time(void){
   struct timeval time;
   do_gettimeofday(&time);
   return usecs_to_jiffies(time.tv_sec * 1000000L + time.tv_usec);
}

/**
 * Initializes Work Queue
**/
static void _init_workqueue(void){
  queue = create_workqueue("runtime_updates");
}

/**
 * Deletes Work Queue
**/
static void _del_work_queue(void){
  if (queue != NULL){
    flush_workqueue(queue);
    // Implement the following for any delayed work
    // cancel_delayed_work_sync(&work);
    destroy_workqueue(queue);
    queue = NULL;
    if(DEBUG) printk(KERN_ALERT "DELETED WORKQUEUE\n");
  }
}

// Bypass Circular Declaration
static void _reg_work(int from_bottom_half);

/**
 * Bottom Half
 * Updates Process Usage and fault counts
**/
static void update_runtimes(void){
  int ret;
  unsigned long utime, stime, current_time;
  unsigned long maj_flt, min_flt;
  long all_maj_flt = 0;
  long allutime = 0;
  long all_min_flt = 0;

  spin_lock(&lock);
  list_for_each_safe(pos, q, &head.list){
    tmp = list_entry(pos, mp_struct, list);
    ret = get_cpu_use(tmp->pid, &min_flt, &maj_flt, &utime, &stime);

    // Updates information if returned, else delete object
    if (!ret) {
      if(stime + utime > 0)
        if(DEBUG) printk(KERN_ALERT "BOTTOM %d %lu %lu\n",tmp->pid, utime, stime);

      tmp->min_flt = min_flt;
      tmp->maj_flt = maj_flt;
      
      tmp->process_usage = utime + stime;
      all_min_flt+=tmp->min_flt;
      all_maj_flt+=tmp->maj_flt;
      allutime+=tmp->process_usage;
    
    } else {
      //Deletes processes that are killed from linked list
      if(DEBUG) printk(KERN_ALERT "BOTTOM HALF DIDN'T FIND %d\n",tmp->pid);
      list_del(pos);
      kfree(tmp);
      list_size--;
    
    }
  }

  // Store updated information with buffer
  current_time = _get_time();
  shared_buffer[shared_index++] = current_time;
  shared_buffer[shared_index++] = all_min_flt;
  shared_buffer[shared_index++] = all_maj_flt;
  
  // Get the total usage of all processes in terms of jiffies
  // Loop around shared buffer for monitor to read (48000)
  shared_buffer[shared_index++] = allutime;// * 100 / (current_time - last_time);
  shared_index %= 48000;
  last_time = current_time;
  spin_unlock(&lock);

  // Call Top Half if its not empty
  if(list_size){
    _reg_work(1);
  }
  
  // Commented out to avoid flooding logs
  // if(DEBUG) printk(KERN_ALERT "FINISHED UPDATING RUNTIMES\n");
}

/**
 * Top Half
 * Queue delayed work to update process usage and fault counts
 *
 * PARAM from_bottom_half boolean value for if top half is called from bottom half
**/
static void _reg_work(int from_bottom_half){
  if ((from_bottom_half && list_size) || (list_size == 1)) {
    struct delayed_work *work = (struct delayed_work *)kmalloc(sizeof(struct delayed_work), GFP_KERNEL);
    if (work) {
       INIT_DELAYED_WORK((struct delayed_work *) work, update_runtimes);
       queue_delayed_work(queue, (struct delayed_work *) work, msecs_to_jiffies(1000/20));
    }
  }
}

/**
 * Proc Filesystem
 * Register User Application
 *
 * PARAM user_message string from user
**/
static void proc_fs_register(char * user_message) {
  int pid;

  sscanf(user_message, "R %u", &pid);
  //Initializes last_time so that it is the correct time apart
  if(list_size == 0){
    last_time = _get_time();
  }

  // Allocate new struct 
  tmp = (mp_struct *)kmalloc(sizeof(mp_struct), GFP_KERNEL);
  tmp->pid = pid;
  tmp->process_usage = 0;
  tmp->maj_flt = 0;
  tmp->min_flt = 0;
  tmp->linuxtask = find_task_by_pid(tmp->pid);

  // Update list_struct
  list_add_tail(&(tmp->list), &(head.list));
  list_size++;

  // Call Top Half
  _reg_work(0);

  if(DEBUG) printk(KERN_ALERT "Registered %d", pid);
}

/**
 * Proc Filesystem
 * Unregister User Application from RMS
 * Frees mp_struct tied to User Application
 *
 * PARAM user_message string from user
**/
static void proc_fs_unregister(char * user_message) {
  int pid;

  sscanf(user_message, "U %u", &pid);

  // Loop through looking for correct mp_struct
  list_for_each_safe(pos, q, &head.list) {
    tmp = list_entry(pos, mp_struct, list);

    // Unregister + Free Memory
    if(tmp->pid == pid) {
      if(DEBUG) printk(KERN_INFO "PROCESS: %d UNREGISTERING", pid);

      // Free Memory
      list_del(pos);
      list_size--;
      kfree(tmp);
      tmp = NULL;
      
      if(DEBUG) printk(KERN_ALERT "PROCESS: %d UNREGISTERED PROPERLY\n", pid);
      return;
    }
  }

  if (list_size == 0) {
    _del_work_queue();
  }
}

/**
 * Proc Filesystem
 * Loops through mp_struct list printing all mp_structs to user
 *
 * RETURN number of bytes left in buffer
**/
static ssize_t mp3_read(struct file *file, char __user *buffer, size_t count, loff_t *ppos){
  int retval;
  if(DEBUG) printk(KERN_INFO "SENDING PIDS");
  
  //If ppos > 0, then that means this is the second time being called and all data has been sent 
  //If list_size == 0, that means the list is empty and we should return immediately
  if((int)*ppos > 0 || !list_size) { 
    return 0; 
  }

  // Loops through mp_struct list
  spin_lock(&lock);
  list_for_each_safe(pos, q, &head.list){
    // Generate string
    char my_buf[BUFSIZE];
    tmp = list_entry(pos, mp_struct, list);
    sprintf(my_buf,"%d\n", tmp->pid);

    // Copy to buffer
    if(DEBUG) printk(KERN_INFO "SENDING %s\n", my_buf);
    if (copy_to_user(buffer + *ppos, my_buf, strlen(my_buf)+1)) {
      return -EFAULT;
    }

    // Update position
    *ppos += strlen(my_buf);
  }
  spin_unlock(&lock);

  //Makes sure that retval is not 0 and it is less than count so that buffer is sent back as intended
  retval = count - *ppos;
  if(DEBUG) printk(KERN_INFO "SENT PIDS");
  return retval;
}

/**
 * Proc Filesystem
 * Recieves PID from user and inits new mp_struct struct
 *
 * RETURN copied data count
**/
static ssize_t mp3_write(struct file *file, const char __user *buffer, size_t count, loff_t *data){
  int to_copy;
  char user_message[count];
  if(DEBUG) printk(KERN_INFO "RECEIVING PID");

  // Initialize memory for new linked list object
  to_copy = copy_from_user(user_message, buffer, count);

  // Proc FS systems
  spin_lock(&lock);
  switch(user_message[0]) {
    case 'R' :
      proc_fs_register(user_message);
      break;
    case 'U' :
      proc_fs_unregister(user_message);
      break;
  }
  spin_unlock(&lock);
  if(DEBUG) printk(KERN_ALERT "PROCESS %c", user_message[0]);

  *data += count - to_copy;
  return count - to_copy;
}

/**
 * Proc Filesystem
 * Function Setup
**/
static const struct file_operations mp_file_fops = {
  .owner = THIS_MODULE,
  .read = mp3_read,
  .write = mp3_write,
};

/**
 * Shared Buffer Filesystem
**/
static int mp3_open(struct inode *inode, struct file *file){
  if(DEBUG) printk(KERN_INFO "MP3 OPEN\n");
  return 0;
}

static int mp3_release(struct inode *inode, struct file *file){
  if(DEBUG) printk(KERN_INFO "MP3 RELEASE\n");
  return 0;
}

static int mp3_mmap(struct file *file, struct vm_area_struct * vm_area){
  int ctr;
  unsigned long pfn;

  if(DEBUG) printk(KERN_INFO "MP3 MMAP\n");
  
  ctr=0;
  for(;ctr < 128; ctr++){
    if(DEBUG) printk(KERN_INFO "MMAP LOOP %d\n", ctr);
    
    pfn = vmalloc_to_pfn((char *)(shared_buffer)+ctr*PAGESIZE);
    
    if(remap_pfn_range(vm_area,(unsigned long)(vm_area->vm_start)+ctr*PAGESIZE,pfn,PAGE_SIZE,PAGE_SHARED)){
      if(DEBUG) printk(KERN_INFO "REMAPPING FAILED\n");
      return -1;
    }
  }

  if(DEBUG) printk(KERN_INFO "END MP3 MMAP\n");

  return 0;
}

static const struct file_operations mp_mmap_fops = {
  .owner = THIS_MODULE,
  .open = mp3_open,
  .release = mp3_release,
  .mmap = mp3_mmap,
};

/**
 * Module Constructor
 * Called when the module is loaded
 * Initializes all necessary variables and allocates necessary memory
**/
int __init mp3_init(void)
{
  int ctr;

  #ifdef DEBUG
  if(DEBUG) printk(KERN_INFO "MODULE LOADING\n");
  #endif

  // Initialize spinlock
  spin_lock_init(&lock);
  if(DEBUG) printk(KERN_INFO "INITIALIZED SPINLOCK\n");

  // Allocate Virtual Buffer and init to -1
  shared_buffer = vmalloc(SHAREDBUFSIZE);
  ctr=0;
  for(;ctr < SHAREDBUFSIZE/LONGSIZE;ctr++){
     shared_buffer[ctr] = -1;
  }

  // Creates Character Device Driver and adds to Kernel
  //cdev_init(&cdevdata, &mp_mmap_fops);
  //ret = cdev_add(&cdevdata, 150, 1);
  //if(DEBUG && ret<0) printk(KERN_INFO "ADDING CDEV FAILED\n");
  register_chrdev(150,"node",&mp_mmap_fops);

  // Creates /proc/mp2/status
  proc_dir = proc_mkdir(DIRECTORY, NULL);
  proc_entry = proc_create(FILENAME, 0666, proc_dir, &mp_file_fops);  
  if(DEBUG) printk(KERN_INFO "CREATED ProcFS\n");

  // Initializes mp_struct head
  INIT_LIST_HEAD(&head.list);
  if(DEBUG) printk(KERN_INFO "INITIALIZE mp_struct head\n");

  // Initialize Workqueue
  _init_workqueue();

  if(DEBUG) printk(KERN_ALERT "MODULE LOADED\n");
  return 0;   
}

/**
 * Module Destructor
 * Called when the module is unloaded
 * Destroys all necessary variables and frees used memory
**/
void __exit mp3_exit(void)
{
  #ifdef DEBUG
  if(DEBUG) printk(KERN_ALERT "MODULE UNLOADING\n");
  #endif

  // Free Buffer
  vfree(shared_buffer);

  // Frees work queue
  _del_work_queue();

  // Deletes Character Device Driver from Kernel
  //cdev_del(&cdevdata);
  unregister_chrdev(150,"node");

  // Deletes /proc/mp3/status
  proc_remove(proc_entry);
  proc_remove(proc_dir);
  if(DEBUG) printk(KERN_INFO "DELETED ProcFS\n");

  // Frees mp_struct memory   
  list_for_each_safe(pos, q, &head.list){
    tmp = list_entry(pos, mp_struct, list);
    list_del(pos);
    kfree(tmp);
  }
  if(DEBUG) printk(KERN_INFO "DELETED struct\n");

  if(DEBUG) printk(KERN_ALERT "MODULE UNLOADED\n");
}

// Register init and exit functions
module_init(mp3_init);
module_exit(mp3_exit);