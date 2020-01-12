#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/device.h>
//semaphore
#include <linux/semaphore.h>
static struct semaphore mys;
//semaphore
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
//
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
//#include <linux/time.h>
//

MODULE_LICENSE("GPL");
MODULE_AUTHOR("farideh");
MODULE_DESCRIPTION("A simple example Linux module.");
MODULE_VERSION("1.00");

#define DEVICE_NAME "OS_char_dev"
#define CLASS_NAME "OS_class"
#define BUF_LEN  1000


static int Major;
static int Device_Open = 0;
static char kernel_buffer[BUF_LEN];
static int buff_in;
static int buff_out;
static int buff_len = 0;
static struct class*  charClass;

///
static int i=0,j=0;
static int bl_or_wh=0;
static char message[200][40];
///
static int device_open(struct inode *inode, struct file *filp);
static int device_release(struct inode *inode, struct file *filp);
static ssize_t device_read(struct file *filp, char *buffer, size_t length,  loff_t *offset);
static ssize_t device_write(struct file *filp, const char *buf, size_t len, loff_t *off);
//netdevice
static unsigned int nf_pre_route_hook( void* priv, struct sk_buff *skb,
        const struct nf_hook_state *state);


static struct nf_hook_ops firewall_ops ;


//netdevice
static struct file_operations fops = {
  .read = device_read,
  .write = device_write,
  .open = device_open,
  .release = device_release
};

//this method is invoked when insmod the module
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

//this method is invoked when rmmod the module
static void __exit lkm_example_exit(void){
  device_destroy(charClass, MKDEV(Major, 0));           // remove the device
  class_unregister(charClass);                          // unregister the device class
  class_destroy(charClass);                             // remove the device class
  unregister_chrdev(Major, DEVICE_NAME);
  printk(KERN_INFO"Goodby OS class\n");
  nf_unregister_net_hook(&init_net,&firewall_ops);
}
//netfilter
static char ip_str[16];
static unsigned int s_port;
static unsigned int s_ip;
static char tmp[50];
static int flag=0;
struct timespec curr_tm;

unsigned int nf_pre_route_hook(  void* priv, struct sk_buff *skb,
        const struct nf_hook_state *state)
{
  struct iphdr *ip = NULL;
  struct udphdr *udp = NULL;
  struct tcphdr *tcp = NULL;
  struct sk_buff *sock_buff;
  sock_buff=skb;
  getnstimeofday(&curr_tm);
  ip=(struct iphdr*)skb_network_header(sock_buff);
  s_ip=(unsigned int)ip->saddr;

  snprintf(ip_str,16,"%pI4",&s_ip);

  //int flag=0;

    if(bl_or_wh==0)
    {



      if (ip->protocol == 17)//UDP
      {

          udp = (struct udphdr *)((__u32*)ip+ip->ihl);
          s_port=htons((unsigned short int) udp->source);

          sprintf(tmp,"%s:%d",ip_str,s_port);
        printk(KERN_INFO "udp:(TIME: %.2lu:%.2lu:%.2lu:%.6lu) Packet recieved ",
                          (curr_tm.tv_sec / 3600) % (24),
                          (curr_tm.tv_sec / 60) % (60),
                          (curr_tm.tv_sec) % (60),
                          (curr_tm.tv_nsec) / (1000));


          for(j=0;j<i;j++)
          {
            printk(KERN_ALERT"tmp in udp is %s",tmp);
            if(strcmp(tmp,message[j])==0)
            {
              printk(KERN_INFO"udp in for:(TIME: %.2lu:%.2lu:%.2lu:%.6lu) Got a new Packet and accepted it due to being in whitelist\n",
                                      (curr_tm.tv_sec / 3600) % (24),
                                      (curr_tm.tv_sec / 60) % (60),
                                      (curr_tm.tv_sec) % 60,
                                      (curr_tm.tv_nsec) / 1000);
              flag=1;
              return NF_ACCEPT;

            }
          }
          if(flag==0)
          {
            printk(KERN_INFO"udp :(TIME: %.2lu:%.2lu:%.2lu:%.6lu) Got a new Packet and droped it......\n",
                                    (curr_tm.tv_sec / 3600) % (24),
                                    (curr_tm.tv_sec / 60) % (60),
                                    (curr_tm.tv_sec) % 60,
                                    (curr_tm.tv_nsec) / 1000);
            return NF_DROP;
          }
          flag=0;

      }
      else if(ip->protocol == 6)//tcp
      {
        tcp= (struct tcphdr *)((__u32 *)ip+ ip->ihl); //this fixed the problem
       s_port = htons((unsigned short int) tcp->source); //sport now has the source port
       sprintf(tmp,"%s:%d",ip_str,s_port);
       printk(KERN_INFO "tcp : (TIME: %.2lu:%.2lu:%.2lu:%.6lu) Packet recieved",
                         (curr_tm.tv_sec / 3600) % (24),
                         (curr_tm.tv_sec / 60) % (60),
                         (curr_tm.tv_sec) % 60,
                         (curr_tm.tv_nsec) / 1000);
                         for(j=0;j<i;j++)
                         {
                           printk(KERN_ALERT"TMP is %s",tmp);
                           if(strcmp(tmp,message[j])==0)
                           {
                             printk(KERN_INFO"(TIME: %.2lu:%.2lu:%.2lu:%.6lu) Got a new Packet and accepted it due to being in whitelist\n",
                                                     (curr_tm.tv_sec / 3600) % (24),
                                                     (curr_tm.tv_sec / 60) % (60),
                                                     (curr_tm.tv_sec) % 60,
                                                     (curr_tm.tv_nsec) / 1000);

                             flag=1;
                             return NF_ACCEPT;

                           }
                         }
                         if(flag==0)
                         {
                           printk(KERN_INFO"tcp:(TIME: %.2lu:%.2lu:%.2lu:%.6lu) Got a new Packet and droped it......\n",
                                                   (curr_tm.tv_sec / 3600) % (24),
                                                   (curr_tm.tv_sec / 60) % (60),
                                                   (curr_tm.tv_sec) % 60,
                                                   (curr_tm.tv_nsec) / 1000);
                           return NF_DROP;
                         }
                         flag=0;
      }//else
      else
      {
        printk(KERN_INFO"(TIME: %.2lu:%.2lu:%.2lu:%.6lu)droped it......\n",
                                (curr_tm.tv_sec / 3600) % (24),
                                (curr_tm.tv_sec / 60) % (60),
                                (curr_tm.tv_sec) % 60,
                                (curr_tm.tv_nsec) / 1000);
        return NF_DROP;
      }




    }
    else
    {

      if (ip->protocol == 17)//UDP
      {

          udp = (struct udphdr *)((__u32*)ip+ip->ihl);
          s_port=htons((unsigned short int) udp->source);

          sprintf(tmp,"%s:%d",ip_str,s_port);
        printk(KERN_INFO "udp:(TIME: %.2lu:%.2lu:%.2lu:%.6lu) Packet recieved",
                          (curr_tm.tv_sec / 3600) % (24),
                          (curr_tm.tv_sec / 60) % (60),
                          (curr_tm.tv_sec) % (60),
                          (curr_tm.tv_nsec) / (1000));
          j=0;
          for(;j<i;j++)
          {
            if(strcmp(tmp,message[j])==0)
            {
              printk(KERN_ALERT"tmp in udp is %s",tmp);
              printk(KERN_INFO"udp:(TIME: %.2lu:%.2lu:%.2lu:%.6lu)  droped it due to being in blacklist\n",
                                      (curr_tm.tv_sec / 3600) % (24),
                                      (curr_tm.tv_sec / 60) % (60),
                                      (curr_tm.tv_sec) % 60,
                                      (curr_tm.tv_nsec) / 1000);
              flag=1;
              return NF_DROP;

            }
          }
          if(flag==0)
          {
            printk(KERN_ALERT"tmp in udp is %s",tmp);
            printk(KERN_INFO"udp:(TIME: %.2lu:%.2lu:%.2lu:%.6lu) accepted it......\n",
                                    (curr_tm.tv_sec / 3600) % (24),
                                    (curr_tm.tv_sec / 60) % (60),
                                    (curr_tm.tv_sec) % 60,
                                    (curr_tm.tv_nsec) / 1000);
            return NF_ACCEPT;
          }
          flag=0;
      }
      else if(ip->protocol == 6)//tcp
      {
        tcp= (struct tcphdr *)((__u32 *)ip+ ip->ihl); //this fixed the problem
       s_port = htons((unsigned short int) tcp->source); //sport now has the source port
       sprintf(tmp,"%s:%d",ip_str,s_port);
       printk(KERN_INFO "tcp:(TIME: %.2lu:%.2lu:%.2lu:%.6lu) Packet recieved",
                         (curr_tm.tv_sec / 3600) % (24),
                         (curr_tm.tv_sec / 60) % (60),
                         (curr_tm.tv_sec) % 60,
                         (curr_tm.tv_nsec) / 1000);
                         j=0;
                         for(;j<i;j++)
                         {
                           printk(KERN_ALERT"tmp in tcp is %s",tmp);
                           if(strcmp(tmp,message[j])==0)
                           {
                             printk(KERN_INFO"tcp:(TIME: %.2lu:%.2lu:%.2lu:%.6lu)  droped it due to being in blacklist\n",
                                                     (curr_tm.tv_sec / 3600) % (24),
                                                     (curr_tm.tv_sec / 60) % (60),
                                                     (curr_tm.tv_sec) % 60,
                                                     (curr_tm.tv_nsec) / 1000);
                             flag=1;
                             return NF_DROP;

                           }
                         }
                         if(flag==0)
                         {
                           printk(KERN_ALERT"tmp in tcp is %s",tmp);
                           printk(KERN_INFO"tcp:(TIME: %.2lu:%.2lu:%.2lu:%.6lu)  accept it......\n",
                                                   (curr_tm.tv_sec / 3600) % (24),
                                                   (curr_tm.tv_sec / 60) % (60),
                                                   (curr_tm.tv_sec) % 60,
                                                   (curr_tm.tv_nsec) / 1000);
                           return NF_ACCEPT;
                         }
                         flag=0;
      }//else
      else
      {
        printk(KERN_INFO"(TIME: %.2lu:%.2lu:%.2lu:%.6lu)  accept it......\n",
                                (curr_tm.tv_sec / 3600) % (24),
                                (curr_tm.tv_sec / 60) % (60),
                                (curr_tm.tv_sec) % 60,
                                (curr_tm.tv_nsec) / 1000);
        return NF_ACCEPT;
      }

    }
    return NF_DROP;//alaki

}

//netfilter
//this method is invoked when the device file is opened in the application
static int device_open(struct inode *inode, struct file *filp)
  {
    down(&mys);//wait of semaphore
    Device_Open++;
    printk(KERN_INFO"device %s is opened\n", DEVICE_NAME);
    return 0;
  }


//this method is invoked when the device file is closed in the application
static int device_release(struct inode *inode, struct file *filp)
{
  Device_Open--;
  printk(KERN_INFO"device %s is closed\n", DEVICE_NAME);
  up(&mys);//signal of semaphore
  return 0;
}


//this method is invoked when reading from the device in application
static ssize_t device_read(struct file *filp, /* see include/linux/fs.h   */
                           char *user_buffer,      /* buffer to fill with data */
                           size_t length,     /* length of the buffer     */
                           loff_t *offset)
{
  printk(KERN_ALERT "Reading from the device %s.\n", DEVICE_NAME);


  if (length<=buff_len){
    copy_to_user(user_buffer, kernel_buffer, length);
    return length;
  }else{
    copy_to_user(user_buffer, kernel_buffer, buff_len);
    //

    //
    return buff_len;
  }



 }


//this method is invoked when writing to the device in application
static ssize_t device_write(struct file *filp, const char *user_buffer, size_t len, loff_t *off)
{
  printk(KERN_ALERT "Writing to the device %s.\n", DEVICE_NAME);
  //
  copy_from_user(kernel_buffer, user_buffer,len);
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
  }


  return len;
}


module_init(lkm_example_init);
module_exit(lkm_example_exit);
