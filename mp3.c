#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include "mp3_given.h"

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
#include <linux/cdev.h>
#include <linux/vmalloc.h>

#define DEBUG 1


MODULE_LICENSE("GPL");
MODULE_AUTHOR("lall3");
MODULE_DESCRIPTION("CS-423 MP2");

//MP3 struct
typedef struct mp3_struct
{
  struct list_head list_node;
  struct task_struct * current_task;
  unsigned long time_used;
  unsigned long major_faults;
  unsigned long minor_faults; 


  pid_t pid;

}mp3_t;

//gloabls
static struct proc_dir_entry *proc_dir_mp3, *proc_dir_status ;// procfs

static long * virtual_buffer;
static int virtual_buffer_index = 0;
//mutex+lock
static struct mutex mp3_mutex;
static spinlock_t mp3_spinlock;

//stores time
static unsigned long time_counter =0;
static struct workqueue_struct * work_queue;
int major_no;
//struct delayed_work * delay_work;
//proc
static int procfs_buffer_size;
static char procfs_buffer[1024];


// Linux Kernel Linked List
static mp3_t head;
static mp3_t *tmp;
static struct list_head *pos, *q;
static int list_size = 0;


//LIST HEAD
//LIST_HEAD(process_list);
/*
* time helper
* returns time in long
*/
static unsigned long get_current_time(void){
   struct timeval temp;
   do_gettimeofday(&temp);
   return usecs_to_jiffies(temp.tv_sec * 1000000L + temp.tv_usec);
}

static void top_half(int arg);
/*
*Bottom half
*
*/
static void delayed_func(void )
{
  static struct list_head *temp1, *temp2;
  static mp3_t * curr;
  int gpu_use;
  unsigned long initial_time, s_time, curr_time, mj_ft, mn_ft;
  long mj_ft_ctr, mn_ft_ctr, total_time;
  mj_ft_ctr = mn_ft_ctr = total_time=0;

  spin_lock(&mp3_spinlock);
  list_for_each_safe(temp1, temp2, &head.list_node)
  {
    curr = list_entry(temp1, mp3_t, list_node);
    gpu_use = get_cpu_use(curr->pid, &mn_ft, &mj_ft, &initial_time, &s_time);

    if(gpu_use ==0)
    {
      curr->minor_faults= mn_ft;
      curr->major_faults= mj_ft;
      curr->time_used = initial_time + s_time;

      mj_ft_ctr += mj_ft;
      mn_ft_ctr += mn_ft;
      total_time += curr->time_used;
    }
    else
    {
      list_del(temp1);
      kfree(curr);
      list_size--;
    }


  }

  curr_time = get_current_time();
  virtual_buffer[virtual_buffer_index]= curr_time;
  virtual_buffer[virtual_buffer_index+1]= mn_ft_ctr;
  virtual_buffer[virtual_buffer_index+2]= mj_ft_ctr;
  virtual_buffer[virtual_buffer_index+3]= total_time;
  virtual_buffer_index += 4;
  virtual_buffer_index %= 48000;
  time_counter = curr_time;
  spin_unlock(&mp3_spinlock);

  if(list_size)
    top_half(1);



}

static void top_half(int arg)
{
  struct delayed_work * d_work;
  if( list_size==1 || (arg && list_size))
  {
    d_work=(struct delayed_work *)kmalloc(sizeof(struct delayed_work), GFP_KERNEL);
    INIT_DELAYED_WORK(d_work , delayed_func);
    queue_delayed_work(work_queue , d_work, msecs_to_jiffies(50) );
  }

}

// ---------FILE OPS--------------------------------------


static void register_pid(int new_pid)
{
  static mp3_t * temp;
  if( !list_size )
    time_counter=get_current_time();

  temp= (mp3_t *)kmalloc(sizeof(mp3_t), GFP_KERNEL);
  temp->pid = new_pid;
  temp->time_used = temp->major_faults = temp->minor_faults =0;
  temp->current_task = find_task_by_pid(new_pid);
  list_size++;
  list_add_tail(&(temp->list_node), &(head.list_node));
  top_half(0);
}

static void unregister_pid(int new_pid)
{
  static struct list_head *temp1, *temp2;
  mp3_t * curr;

  list_for_each_safe(temp1, temp2, &head.list_node)
  {
    curr = list_entry(temp1, mp3_t, list_node);
    if(curr->pid == new_pid)
    {
      list_del(temp1);
      kfree(curr);
      list_size--;
      curr=NULL;
    }
  }

  if(list_size==0)
  {
    flush_workqueue(work_queue);
    destroy_workqueue(work_queue);
    work_queue=NULL;

  }
}

/*
* Write function
*/
static ssize_t pfile_write(struct file *file,const  char __user *buffer, size_t count, loff_t * data)
{

  char from_user[count];
  int ctr= copy_from_user(from_user , buffer , count);
  char c = from_user[0];

  pid_t new_pid;
  printk(KERN_ALERT "WRITE FUNCTION REACHED");

  sscanf(from_user, "%c %u", &c ,&new_pid);
  //locking critical section
  spin_lock(&mp3_spinlock);
  if(c == 'R')
  {
    printk(KERN_ALERT "Registering %d", new_pid);
    register_pid(new_pid);
    printk(KERN_ALERT "Registered %d", new_pid);
  }
  else if(c == 'U')
  {
    printk(KERN_ALERT "Unregistering %d", new_pid);
    unregister_pid(new_pid);
    printk(KERN_ALERT "Unregistered %d", new_pid);
  }
  else 
    printk("Unknown Command %c", c);
  spin_unlock(&mp3_spinlock);

  *data += count - ctr;
  return count - ctr;





}
//-----------------------------------------------------------------------
//File struct, read and write
/*
* File read function
* bux fixed from MP1
*/
static ssize_t pfile_read(struct file *file, char __user * buf, size_t count, loff_t * data)
{
  static struct list_head *temp1, *temp2;
  mp3_t * curr;
  char to_read[256];
  if(list_size ==0)
    return 0;

  printk(KERN_ALERT "READ FUNCTION REACHED");
  spin_lock(&mp3_spinlock);

  list_for_each_safe(temp1, temp2, &head.list_node)
  {
    curr= list_entry(temp1 , mp3_t, list_node);
    sprintf(to_read , "%d\n" , curr->pid);
    copy_to_user(buf+ *data, to_read, strlen(to_read)+1);
    *data += strlen(to_read);
  }
  spin_unlock(&mp3_spinlock);
  return count - *data;

}


static const struct file_operations mp3_file_fops = {
  .owner = THIS_MODULE,
  .read = pfile_read,
  .write = pfile_write,
};

/*
* mp2_init - Called when module is loaded
*/
int __init mp3_init(void)
{
  int idx=0;
   #ifdef DEBUG
   printk(KERN_ALERT "MP3 MODULE LOADING\n");
   #endif

   //proc setup
   proc_dir_mp3 = proc_mkdir( "mp3" ,NULL);
   proc_dir_status = proc_create("status", 0666, proc_dir_mp3, &mp3_file_fops);


   work_queue = create_workqueue("work_queue");

   spin_lock_init(&mp3_spinlock);
   mutex_init(&mp3_mutex);
   virtual_buffer = vmalloc(512*1024); 
   while(idx< 512*1024/(sizeof(long) ))
   {
    virtual_buffer[idx]=-1;
    idx++;
   }

	

   INIT_LIST_HEAD(&head.list_node);

   printk(KERN_ALERT "MP3 MODULE LOADED\n");
   return 0;
}


/*
* mp2_exit - Called when module is unloaded
*
*/
void __exit mp3_exit(void)
{
   struct list_head * pos1, * pos2;
   mp3_t * curr;
   #ifdef DEBUG
   printk(KERN_ALERT "MP3 MODULE UNLOADING\n");
   #endif


  
   remove_proc_entry("status", proc_dir_mp3);
   remove_proc_entry("mp3", NULL);

   vfree(virtual_buffer);

   list_for_each_safe(pos1, pos2, &head.list_node ) {
        curr= list_entry(pos1, mp3_t , list_node);
        list_del(pos1);
        kfree(curr);
    }
  

   /*
   dev_t dev;
	cdev_del(&char_device);*/

   flush_workqueue(work_queue);
   destroy_workqueue(work_queue);

   mutex_destroy(&mp3_mutex);
   printk(KERN_ALERT "MP3 MODULE UNLOADED\n");
}

// Register init and exit funtions
module_init(mp3_init);
module_exit(mp3_exit);