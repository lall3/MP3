#define LINUX

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/mm.h>

#include "mp3_given.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("g18");
MODULE_DESCRIPTION("CS-423 MP3");

#define DEBUG 1
#define FILENAME "status"
#define DIRECTORY "mp3"
#define PROCFS_SIZE_MAX 1024
#define SUCCESS 0
#define DEV_NAME "mp3_dev"
#define WORK_FREQ 20
#define BUFFER_SIZE (256*4096)

/* structs */
typedef struct mp3_task_struct {
    struct task_struct* linux_task;
    unsigned long pid;
    unsigned long major_fc;
    unsigned long minor_fc;
    unsigned long util;
    struct list_head list;
} mp3_task_struct_t;


/* function prototypes */
static int read_proc_callback (struct file *file, char __user *buffer, size_t count, loff_t *data);
static int write_proc_callback (struct file *file, const char __user *buffer, size_t count, loff_t *data);
int register_proc (unsigned long pid);
int deregister_proc (unsigned long pid);
void destroy_proc_list(void);
void delete_task (mp3_task_struct_t *ts);
static void work_handler(struct work_struct* arg);
void schedule_work_ours(void);
void write_to_buffer(void);
void update_cpu_use(void);

/* character device functions */
static int dev_open(struct inode *inode, struct file *file) {return SUCCESS;}
static int dev_close(struct inode *inode, struct file *file) {return SUCCESS;}
static int dev_mmap(struct file *file, struct vm_area_struct *vm);

/* file operations */
static const struct file_operations mp3_file = {
    .owner = THIS_MODULE,
    .read = read_proc_callback,
    .write = write_proc_callback,
};
static struct file_operations dev_fops = {
    .owner = THIS_MODULE,
    .open = dev_open,
    .release = dev_close,
    .mmap = dev_mmap
};

/* global variables */
static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_entry;
static int procfs_buffer_size;
static char procfs_buffer[PROCFS_SIZE_MAX];
struct mutex m;
unsigned long * buffer;
struct delayed_work * work;
struct workqueue_struct * queue;
static struct cdev mp3_cdev;
int last_sample = 0;
int major_num;

/* initialize list_head */
LIST_HEAD(proc_list);

static int dev_mmap(struct file *file, struct vm_area_struct *vm) {
    void *ptr = buffer;
    unsigned long pfn, size;
    unsigned long curr = vm->vm_start;
    unsigned long end = vm->vm_end;
    unsigned long len = curr - end;
    int err;
    
    pfn = vmalloc_to_page(ptr);

    printk("start mapping dev_mmap\n");

    while (curr != end) {
        vm_insert_page(vm, curr, pfn);
        curr += PAGE_SIZE;
        ptr += PAGE_SIZE;

        // get physical page address of the buffer
        pfn = vmalloc_to_page(ptr);
    }
    return SUCCESS;
}

/**
 * bottom half, write data into buffer
 * @param arg [description]
 */
static void work_handler(struct work_struct * arg){
    update_cpu_use();
    write_to_buffer();
    schedule_work_ours();
}
void write_to_buffer(){
    unsigned long major = 0;
    unsigned long minor = 0;
    unsigned long util = 0;
    unsigned long * write;
    mp3_task_struct_t* ts = NULL;
    mp3_task_struct_t* tmp = NULL;
    
    mutex_lock(&m);
    list_for_each_entry_safe(ts, tmp, &proc_list, list) {
        major += ts->major_fc;
        minor += ts->minor_fc;
        util += ts->util;
    }
    write = buffer + last_sample*4;
    *write = jiffies;
    write[1] = major;
    write[2] = minor;
    write[3] = util;
    last_sample++;
    mutex_unlock(&m);
}
 

void update_cpu_use(){
    unsigned long time;
    unsigned long major;
    unsigned long minor;
    unsigned long util;
    long unsigned int check;
    int pid;


    mp3_task_struct_t* ts = NULL;
    mp3_task_struct_t* tmp = NULL;
    
    mutex_lock(&m);

    list_for_each_entry_safe(ts, tmp, &proc_list, list) {
        pid = ts->pid;
        check = get_cpu_use(pid, &minor, &major, &util, &time);
        if(check==-1){
            printk(KERN_ALERT  "invalid PID");
        }
        ts->util = util;
        ts->major_fc = major;
        ts->minor_fc = minor;
    } 
    mutex_unlock(&m);
}

/**
 * Registration
 */
int register_proc (unsigned long pid) {

    //check if list is empty
    int empty = list_empty_careful(&proc_list); 
    mp3_task_struct_t *new_mp3_task;

    printk("register %lu \n", pid);

    new_mp3_task = kmalloc(sizeof(mp3_task_struct_t), GFP_KERNEL);
    new_mp3_task->pid = pid;
    new_mp3_task->linux_task = find_task_by_pid(pid);

    mutex_lock(&m);
    list_add_tail(&new_mp3_task->list, &proc_list);
    mutex_unlock(&m);

    //if list previously empty then create work queue job
    if (empty){ 
        schedule_work_ours();
    }
    
   return 0;
}

void schedule_work_ours(){
    //printk("schedule work \n");
    INIT_DELAYED_WORK(work, work_handler);
    queue_delayed_work(queue, work, HZ/WORK_FREQ);
}

int deregister_proc (unsigned long pid) {
    mp3_task_struct_t* ts = NULL;
    mp3_task_struct_t* tmp = NULL;

    printk("deregister %lu \n", pid);

    mutex_lock(&m);
    list_for_each_entry_safe(ts, tmp, &proc_list, list) {
        if (ts->pid == pid){
             list_del(&ts->list);
            kfree(ts);
        }
    }
    if (list_empty_careful(&proc_list)) {
        cancel_delayed_work_sync(work);
    }

    mutex_unlock(&m);
    
    return 0;
    
}

static int read_proc_callback (struct file *file, char __user *buffer, size_t count, loff_t *data) {
    mp3_task_struct_t* ts = NULL;
    mp3_task_struct_t* tmp =NULL;

    int copied = 0;
    char* buf = (char*) kmalloc(PROCFS_SIZE_MAX, GFP_KERNEL);

    printk("read callback \n");

    mutex_lock(&m);
    list_for_each_entry_safe(ts, tmp, &proc_list, list) {
        copied += sprintf(buf+copied, "%lu\n ", ts->pid);
    }
    //send to user buffer
    copy_to_user(buffer, buf, copied);
    printk(KERN_INFO "copied = %s\n", buffer);
    mutex_unlock(&m);

    kfree(buf);
    return copied;
}

static int write_proc_callback (struct file *file, const char __user *buffer, size_t count, loff_t *data) {
    //– For REGISTRATION: “R<PID>”
    //– For UNREGISTRATION: “U<PID>”
    unsigned long utilization = 0;
    unsigned long major_fc = 0;
    long int pid = 0;
   
    procfs_buffer_size = count;

    if (procfs_buffer_size > PROCFS_SIZE_MAX) {
        procfs_buffer_size = PROCFS_SIZE_MAX;
    }

    if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size)) {
        return -EFAULT;
    }
    procfs_buffer[count-1] = '\0';

    // parse buffer to long
    if(strict_strtol(buffer+2, 0, &pid))
        return -EFAULT;
    
    printk("%lu", pid);
    
    switch(procfs_buffer[0]) {
        case 'R': {
            printk(KERN_INFO "REGISTER %lu \n",pid);
            if(register_proc(pid)<0) {
                printk(KERN_ALERT "write_proc_callback:: cannot register process %lu \n", pid);
                return -EINVAL;
            }
            break;
        }
        case 'U': {
            printk(KERN_INFO "UNREGISTER: %lu\n",pid);
            if(deregister_proc(pid)<0) {
                printk(KERN_ALERT "write_proc_callback:: Failed to unregister process %lu\n ", pid);
                return -EINVAL;
            }
            break;
        }
         default: {   
            printk(KERN_ALERT "write_proc_callback:: INVALID VALUE\n");
            return -EINVAL;
        }
    }
    return procfs_buffer_size;
}

static int __init mp3_init(void) {

    int err = 0;
    dev_t dev;

 //might refactor my code, I need to double check that our VM runs at 60 jiffies a second
 //unsigned long ring = 3;
 //timer(ring);

    mutex_init(&m);
    
    // create filesystem entries
    proc_dir = proc_mkdir(DIRECTORY, NULL);
    proc_entry = proc_create(FILENAME, 0666, proc_dir, &mp3_file);

    // return error if proc_entry not created
    if (!proc_entry) {
        proc_remove(proc_dir);
        printk(KERN_ALERT "Failed to create entry \\proc\\%s\\%s\n", DIRECTORY, FILENAME);
        return -ENOMEM;
    }
    buffer = vzalloc(BUFFER_SIZE);

    // initialize work/work queue
    queue =  create_singlethread_workqueue("queue");
    work = kmalloc(sizeof(struct work_struct),GFP_KERNEL);
    
    // initialize character device driver
    if ((err = alloc_chrdev_region(&dev, 0, 1, DEV_NAME))) {
        printk("alloc_chrdev_region failed. err num: %d", err);
        return err;
    }
    cdev_init(&mp3_cdev, &dev_fops);
    if ((err = cdev_add(&mp3_cdev, dev, 1))) {
        printk("cdev_add failed. err num: %d", err);
        return err;
    }
    


    printk(KERN_ALERT "MP3 MODULE LOADED\n");
    return 0;
}

static void __exit mp3_exit(void) {
    dev_t dev;

    printk(KERN_ALERT "MP3 MODULE UNLOADING\n");
    destroy_proc_list();

    // remove proc filesystem entries
    proc_remove(proc_entry);
    proc_remove(proc_dir);
    vfree(buffer);

    // free workqueue
    flush_workqueue(queue);
    destroy_workqueue(queue);

    
    // free character device driver
    dev = mp3_cdev.dev;
    cdev_del(&mp3_cdev);
    
    unregister_chrdev_region(dev, 1);

    // destroy proc list
    destroy_proc_list();

    printk(KERN_ALERT "MP3 MODULE UNLOADED\n");
}

module_init(mp3_init);
module_exit(mp3_exit);