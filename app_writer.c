#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include<fcntl.h>

int main(){
  char buff[256];
  int conf = open("conf.txt",O_RDWR);
  if(conf>0)
  {
    read(conf, buff,256);
    printf("buffer is : %s\n",buff );
  }
  int dev = open("/dev/OS_char_dev",O_RDWR);
  if (dev<0)
    printf("error openning the device\n");
  
  char *string,*found;
  string=(char*)malloc(400);
  found=(char*)malloc(400);
  int  i=0;
  sprintf(string , "%s",buff);

  found = strsep(&string,"\n");

  write(dev, found, strlen(found)+1);
  while( (found = strsep(&string,"\n")) != NULL )
  {
    
      write(dev, found, strlen(found)+1);
      printf("ok\n");
    }
  
  close(dev);
}
