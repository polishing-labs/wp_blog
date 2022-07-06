---
title: Mix-WP
date: 2022/7/4 14:46:25
tags:
 - Web
 - Misc
categories:
 - BUU
---
# Mix-WP

## web

### [强网杯 2019]随便注1

首先是判断语句闭合方式，输入1、1’、1’#判断，结果语句应该为单引号闭合。

![image-20220628223542110](/upload/img/image-20220628223542110.png)

再判断列1’ order by1,2,3…–+，发现到3时报错，所以列数位为2

![image-20220628224815026](/upload/img/image-20220628224815026.png)

然后联合注入，1’ union select 1,databases()--+ 。返回过滤提示。

![image-20220628225148290](/upload/img/image-20220628225148290.png)

发现select被过滤，然后尝试堆叠注入

查看数据库

![image-20220628225738077](/upload/img/image-20220628225738077.png)

查表

![image-20220628225912892](/upload/img/image-20220628225912892.png)

看word字段

![image-20220628230038653](/upload/img/image-20220628230038653.png)

查看表1919810931114514的字段，这里1919810931114514必须用反单引号括起来

![image-20220628230155054](/upload/img/image-20220628230155054.png)

因为一般SQL代码中会有这么一段select * from （表名） where = 变量，当通过注入后会变成select * from （表名）  where id = 变量 OR 1=1，就会使百where后面的表达式变成一句可有可无的表达式，因为or前面执行成功，且1=1为真。不会报错。就与select * from （表名）相等然后就可以通过这种句式来取得当前数据表中所有的用户信息答。

但是这个办法行不通

![image-20220628230727049](/upload/img/image-20220628230727049.png)

然后表words有两列，列名为 “id” 和 “data” 而表1919810931114514只有一列 “flag” 。而且可以发现，它是通过 “id” 来索引的，通过输入1时的回显和展示表words的内容可以判断。而且没有过滤 alter 和 rename。可以修改表名和列名。那么我们不妨我们把表 words 改名为其它，然后把表 1919810931114514 改名为 words ，再在表 1919810931114514 插入一列 id ，或直接将列 flag 改名为 id ，当我们再次查询时，不就是查询 flag 所在表了吗，且可以被展示出来。

所以我们构造payload

-1';rename table `words` to `words1`;rename table `1919810931114514` to `words`;alter table `words` change `flag` `id` varchar(100) character set utf8 collate utf8_general_ci not NULL;#

然后再用上面1' or 1=1# 这个方法就可以了

![image-20220628230957330](/upload/img/image-20220628230957330.png)



### [SUCTF 2019]EasySQL1

先试试1
![在这里插入图片描述](https://img-blog.csdnimg.cn/20200922174402870.png#pic_center)

有回显
再试试字母
![image-20220628231358360](/upload/img/image-20220628231358360.png)

没有回显
（试试单引号注入
![image-20220628231415277](/upload/img/image-20220628231415277.png)

提示不一样，因此猜测这里有注入点
（4）试试有多少列
![image-20220628231430879](/upload/img/image-20220628231430879.png)

还是不成功，因此一般的联合查询在这里不能使用
（5）基于时间的盲注和报错注入都需要嵌套联合查询语句来实现，因此可以跳过，直接试试布尔型盲注
![image-20220628231445277](/upload/img/image-20220628231445277.png)

还是不成功
看了别人的wp之后才知道：sql_mode 设置了 PIPES_AS_CONCAT 时，|| 就是字符串连接符，相当于CONCAT() 函数
当 sql_mode 没有设置 PIPES_AS_CONCAT 时 （默认没有设置），|| 就是逻辑或，相当于OR函数
第一种就按默认没有配置来进行，此时||就是逻辑或因此只需要将

**$_POST[‘query’]** 提交的数据换成*,1

sql语句就变成了select *,1||flag from Flag，
 就是select *,1 from Flag，这样就直接查询出了Flag表中的所有内容。
 此处的1是临时增加一列，列名为1且这一列的所有值都为1

![image-20220628231748484](/upload/img/image-20220628231748484.png)

### [极客大挑战 2019]LoveSQL1

尝试使用语句1' or 1#看看是否可以登录

![image-20220628231905901](/upload/img/image-20220628231905901.png)

发现可以成功登录，然后就是order by找到了回显点

![image-20220628232208553](/upload/img/image-20220628232208553.png)

然后就是爆库名

![image-20220628232149449](/upload/img/image-20220628232149449.png)

接着就是爆表名

![image-20220628232248899](/upload/img/image-20220628232248899.png)

最后成功解出，这里字比较难看，就打开了网页源代码，进行查看。

![image-20220628232314858](/upload/img/image-20220628232314858.png)

### [极客大挑战 2019]Havefun1

首先打开页面是一只小猫

![image-20220701182928306](/upload/img/image-20220701182928306.png)

发现页面上并没有什么有用的消息，然后就去查看网页源代码

![image-20220701183150061](/upload/img/image-20220701183150061.png)

所以用get传参的方式，并且cat=dog，就能得到flag

### [ACTF2020 新生赛]Exec1

这道题首先是考察命令注入

首先尝试服务器ping自己

![image-20220705154130646](/upload/img/image-20220705154130646.png)

尝试在ping命令后增加别的命令

127.0.0.1;ls

![image-20220705154233424](/upload/img/image-20220705154233424.png)

127.0.0.1;ls /用ls命令来查看所有的目录

![image-20220705154506604](/upload/img/image-20220705154506604.png)

tac命令与cat命令类似是显示或连接多个文本文件

![image-20220705154717369](/upload/img/image-20220705154717369.png)

### [极客大挑战 2019]Secret File1

![image-20220704233308906](/upload/img/image-20220704233308906.png)

打开之后是这样的页面，题目提示说去找，页面没发现什么东西，直接看源代码了

![image-20220704233458304](/upload/img/image-20220704233458304.png)

看到这里有一个文件，直接访问看看有什么东西

![image-20220704233843358](/upload/img/image-20220704233843358.png)

然后就点击查看了

![image-20220704233928924](/upload/img/image-20220704233928924.png)

根据页面提示反复了好几次，一直没找到突破口，看了师傅的wp恍然大悟用抓包

![image-20220704235501834](/upload/img/image-20220704235501834.png)

抓到报文后

![image-20220704235537948](/upload/img/image-20220704235537948.png)

发现有一个secre3t.php访问一下

![image-20220704235631089](/upload/img/image-20220704235631089.png)

联想到php伪协议，构造payload:?file=php://filter/read=convert.base64-encode/resource=flag.php

![image-20220704235813258](/upload/img/image-20220704235813258.png)

base64加密

![image-20220704235845128](/upload/img/image-20220704235845128.png)

得到flag



## misc

### FLAG

![42011487927629132](C:\Users\DELL\Desktop\42011487927629132.png)

图片用stegsolve打开后，发现是LSB隐写

![image-20220628214001800](/upload/img/image-20220628214001800.png)

这里有一个PK的东西，实际上就是ZIP文件504B0304转化成ASCII码的形式，用save bin保存为zip文件，把压缩文件里的文件解压出来

![在这里插入图片描述](https://img-blog.csdnimg.cn/20190614205627661.png)

直接用strings查看字符串![image-20220628215859243](/upload/img/image-20220628215859243.png)



或者可以放到IDEA里![image-20220628215922204](/upload/img/image-20220628215922204.png)



### 面具下的flag

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210214161947870.jpg)

打开010editor，发现了一个文件

![image-20220628215551500](/upload/img/image-20220628215551500.png)

然后用kali中的binwalk进行文件分离

<img src="/upload/img/image-20220628220342636.png" alt="image-20220628220342636" style="zoom: 200%;" />



分离出压缩包，且存在伪加密，09 改为 00 解除伪加密，压缩包里面是一个vmdk类型的文件,之前没见过这种类型的文件，百度了一下，知道这种文件可以用 7z 进行解压提取，在kali中使用 7z 解压：

![image-20220628220448568](/upload/img/image-20220628220448568.png)

得到几个文件夹，其中 key_part_one 和 key_part_two 中含有Brainfuck与Ook!的加密文本 ，解密后将得到的字符串前拼接起来就得到了flag。

![image-20220628220517653](/upload/img/image-20220628220517653.png)

### 假如给我三天光明

![image-20220629192348453](/upload/img/image-20220629192348453.png)

打开图片思路就比较清楚了，根据题目以及常识知道海伦凯勒是盲人，下面的应该就是盲文

![image-20220629195056836](/upload/img/image-20220629195056836.png)

根据盲文对照表解出来是kmdonowg，然后用这个解开压缩包，打开压缩包之后，发现是一个音频文件，打开听了一下发现是摩斯密码然后用audacity打开

![image-20220630120604233](/upload/img/image-20220630120604233.png)

根据摩斯密码的规律推断出

-.-./-/..-./.--/.--././../-----/---../--.../...--/..---/..--../..---/...--/-../--..

再将其进行转译

CTFWPEI08732?23DZ

将大写全部都转化为小写，最终得到flag