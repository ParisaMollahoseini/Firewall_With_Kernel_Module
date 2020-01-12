# Building simple firewall with kernel module

## What do we need in general:

1. Module code
2. Config file named **conf.txt** for writing type of firewall(*blacklist or whitelist*) and list of ip:port .
3. Program for reading from a file (*"conf.txt"*) and writing to the module .
4. Writing Makefile

### First we make a conf.txt with code bellow:

```
gedit conf.txt
```

Then we fill it like this:

**blacklist(or whitelist)
127.0.0.1:53
8.8.8.8:80
...**

### Second we can write user space code named *app_writer.c*

#### What is in app_writer.c

  -Reading from **"conf.txt"**
  -Store that string in char* named "buf"
  -Open module file with address **/dev/OS_char_dev** for writing in it
  -Seperate each line of "buf" with function *strsep*
  -Send each line to module with write function
  -Close module file

### Third we write kernel module

### Module have two parts :

  -Network
  -Char device

#### Network part

##### Libraries that should be included :
```
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/time.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
```
#### Global variables
```
static int Major;
static int Device_Open = 0;
static char kernel_buffer[BUF_LEN];
static int buff_in;
static int buff_out;
static int buff_len = 0;
static struct class*  charClass;

static int i=0,j=0;//counter in message string
static int bl_or_wh=0;// list is black or white
static char message[200][40];//string for keeping ip:ports

//netfilter
static char ip_str[16];
static unsigned int s_port;
static unsigned int s_ip;
static char tmp[50];
static int flag=0;
struct timespec curr_tm;// time of sending log
```
### What is netfilter

It is a subsystem of Linux kernel for filtering network packets .
It is possible to define some hooks in route of packets.
There is 5 points in network that can be chosen for being hook.

List of hooks points with their names:
1. NF_INET_PRE_ROUTING
  It includes all kind of arriving packets.
2. NF_INET_LOCAL_IN
  It includes all packets which destinations are this system.
3. NF_INET_FORWARD
  It includes all packets which destinations are not this system.
4. NF_INET_POST_ROUTING
  It includes all output packets.
5. NF_INET_LOCAL_OUT
  It includes all output packets from our system network stack

When each hook is defined , should decide what to do for following way .

It can make these decision:

  -NF_DROP
  -NF_ACCEPT
  -...

We just use two first commands.


#### Now we use hook function which is defined like this:
```
static unsigned int nf_pre_route_hook( void* priv, struct sk_buff *skb,
        const struct nf_hook_state *state);

```
**skb** is used for catching ip , port , protocol , and information about packets.
In this function we will use NF_DROP and NF_ACCEPT commands for filtering packets.

#### We also use nf_hook_ops which has useful functions in it :
```
static struct nf_hook_ops firewall_ops ;
```
With these members:
```
firewall_ops.pf = PF_INET;
firewall_ops.priority = NF_IP_PRI_FIRST;
firewall_ops.hooknum =0;// number of hook points said at the top
firewall_ops.hook = nf_pre_route_hook;
```

### What is char device module

It is used for working with files in kernel space .

#### First we should define a structure like bellow:

```
static struct file_operations fops = {
  .read = device_read,// it is unused in this program
  .write = device_write,
  .open = device_open,
  .release = device_release
};
```
Then we should implement each of them .

#### Write function
read the *string* from kernel file which is sent by app_writer.c
```
static ssize_t device_write(struct file *filp, const char *user_buffer, size_t len, loff_t *off)
{
  printk(KERN_ALERT "Writing to the device %s.\n", DEVICE_NAME);
  //
  copy_from_user(kernel_buffer, user_buffer,len);//read buffer from user .
  buff_len = len;

  if((strcmp(kernel_buffer,"whitelist")==0) | (strcmp(kernel_buffer,"blacklist")==0))
  {
    if(strcmp(kernel_buffer,"blacklist")==0)
    bl_or_wh=1;//black
    else{
      bl_or_wh=0;
    }
  }
  else
  {
      printk(KERN_ALERT "my buffer %s\n", kernel_buffer);
      sprintf(message[i++],"%s",kernel_buffer);
  }//this will complete char* message that has list of ip:ports


  return len;
}
```
#### Open function
This method is invoked when the device file is opened in the application
```
static int device_open(struct inode *inode, struct file *filp)
  {
    down(&mys);//wait of semaphore
    Device_Open++;
    printk(KERN_INFO"device %s is opened\n", DEVICE_NAME);
    return 0;
  }

```
We use **semaphore** for blocking open function when several users come and want to use module and write on it .


#### Release function
This method is invoked when the device file is closed in the application.
```
static int device_release(struct inode *inode, struct file *filp)
{
  Device_Open--;
  printk(KERN_INFO"device %s is closed\n", DEVICE_NAME);
  up(&mys);//signal of semaphore
  return 0;
}

```

We use **semaphore** for unblocking release function when several users come and want to use module and write on it .

***Futher more we should add init and exit functions to this module . They are used when module is created or removed .***

### Init function
We initialize some members of firewall_ops structure and register char device and net hook .

```
static int __init lkm_example_init(void) {
  sema_init(&mys,1);//initialize semaphore
  printk(KERN_INFO "Hello OS class\n");
  firewall_ops.pf = PF_INET;
  firewall_ops.priority = NF_IP_PRI_FIRST;
  firewall_ops.hooknum =0;
  firewall_ops.hook = nf_pre_route_hook;
  Major = register_chrdev(0, DEVICE_NAME, &fops);

  if (Major < 0) {
    printk(KERN_ALERT "Registering char device failed with %d\n", Major);
    return Major;
  }
  charClass = class_create(THIS_MODULE, CLASS_NAME);
  if(charClass==NULL){
    printk(KERN_ALERT "can not make class for the device %s",DEVICE_NAME);
    unregister_chrdev(Major, DEVICE_NAME);
    return -1;
  }
  if(device_create(charClass, NULL, MKDEV(Major, 0), NULL, DEVICE_NAME)==NULL){
    printk(KERN_ALERT "can not make node for device %s",DEVICE_NAME);
    unregister_chrdev(Major, DEVICE_NAME);
    return -1;
  }

  buff_in = 0;
  buff_out = 0;
  printk(KERN_INFO "I was assigned major number %d. To talk to\n", Major);

return nf_register_net_hook(&init_net,&firewall_ops);
}
```
### Exit function
This method is invoked when remove the module and unregister char device and net hook .
```
static void __exit lkm_example_exit(void){
  device_destroy(charClass, MKDEV(Major, 0));           // remove the device
  class_unregister(charClass);                          // unregister the device class
  class_destroy(charClass);                             // remove the device class
  unregister_chrdev(Major, DEVICE_NAME);
  printk(KERN_INFO"Goodby OS class\n");
  nf_unregister_net_hook(&init_net,&firewall_ops);
}
```

#### *"printk"* in module programming is used for log .


## How to run

1. Write these in terminal :
```
make
sudo insmod myModule.ko
gcc app_writer.c -o app_writer
```

2. Open another terminal and write :
```
jounalctl -f
```
*It shows kernel logs*

3. Open a browser and write an ip or address of the site on it .
According to type of firewall(black or white) you can see you site will be dropped or accepted in browser or in jounalctl which is opened in second terminal.

## Reference

[my github](https://github.com/parisa1377/bootloader).
