# EBurst 0.1

这个脚本主要提供对Exchange邮件服务器的账户爆破功能，集成了现有主流接口的爆破方式。

## 作者 ##

咚咚呛 

如有其他建议，可联系微信280495355

## 技术细节 ##
技术细节如下

	1、支持多线程爆破
	2、支持字典爆破
	3、支持爆破漏洞验证功能
	4、支持爆破的接口如下：
	    https://Exchangeserver/ecp
        https://Exchangeserver/ews
        https://Exchangeserver/oab
        https://Exchangeserver/owa
        https://Exchangeserver/rpc
        https://Exchangeserver/api
        https://Exchangeserver/mapi
        https://Exchangeserver/powershell
	    https://Exchangeserver/autodiscover
	    https://Exchangeserver/Microsoft-Server-ActiveSync
    

## 使用 ##
技术细节如下

程序下载

> root# <kbd>git clone https://github.com/grayddq/GScan.git</kbd>
>
> root# <kbd>cd GScan</kbd>

参数参考

>      sh-3.2# python EBurst.py
>       Usage: EBurst.py [options]
>       
>       Options:
>        -h, --help            show this help message and exit
>        -d DOMAIN             邮箱地址
>        -L USERFILE           用户文件
>        -P PASSFILE           密码文件
>        -l USER               指定用户名
>        -p PASSWORD           指定密码
>        -T THREAD, --t=THREAD
>                              线程数量，默认为10
>        -C, --c               验证各接口是否存在爆破的可能性
>      
>        type:
>          EBurst 扫描所用的接口
>       
>           --autodiscover      autodiscover接口，自Exchange Server 2007开始推出的一项自动服务，用于自动配置
>                               用户在Outlook中邮箱的相关设置，简化用户登陆使用邮箱的流程。
>           --ews               ews接口，Exchange Web Service,实现客户端与服务端之间基于HTTP的SOAP交互
>           --mapi              mapi接口，Outlook连接Exchange的默认方式，在2013和2013之后开始使用，2010
>                               sp2同样支持
>           --activesync        activesync接口，用于移动应用程序访问电子邮件
>           --oab               oab接口，用于为Outlook客户端提供地址簿的副本，减轻Exchange的负担
>           --rpc               rpc接口，早期的Outlook还使用称为Outlook Anywhere的RPC交互
>           --api               api接口
>           --owa               owa接口，Exchange owa 接口，用于通过web应用程序访问邮件、日历、任务和联系人等
>           --powershell        powershell接口，用于服务器管理的Exchange管理控制台
>           --ecp               ecp接口，Exchange管理中心，管理员用于管理组织中的Exchange的Web控制台
>       sh-3.2#




## 程序运行截图 ##

![Screenshot](pic/111.png)

![Screenshot](pic/222.png)

