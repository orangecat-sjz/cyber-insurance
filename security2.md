# MulVAL: A Logic-based Network Security Analyzer

## 简介

MulVAL是一个基于逻辑的网络安全分析工具，旨在帮助用户有效地识别和防范网络威胁。MulVAL结合了漏洞扫描、推理引擎等技术，并通过对特定漏洞和攻击方式进行建模和规则定义来推理网络中的安全状态和威胁情报。

## MulVAL的组成部分

- OVAL漏洞描述语言和扫描器：用于描述和扫描主机和应用程序的漏洞信息，并输出详细的机器配置信息。

  - 网络配置结构化输入：networkService(Host, Program, Protocol, Port, Priv)，clientProgram(Host, Program, Priv)，setuidProgram(Host, Program, Owner)，filePath(H, Owner, Path)，nfsExport(Server, Path, Access, Client)，nfsMountTable(Client, ClientPath, Server, ServerPath)
  - 提供HACL列表用于网络连接的分析。hacl(Source, Destination, Protocol, DestPort).

- ICAT漏洞数据库漏洞描述，由CVE-ID直接引用：

  - 最关键的信息结构：漏洞名，ICAT条目（包括exploitable range: local, remote， consequence: confidentiality loss, integrity loss, denial of service, and privilege escalation）
- 基于prologue逻辑语言，使用ICAT条目，定义漏洞的脆弱性和后果，定义漏洞存在性谓词，并使用霍恩子句将所有条件连接起来进入推理系统。vulExists(webServer, ’CVE-2002-0392’, httpd)，vulProperty(’CVE-2004-00495’, localExploit, privEscalation).
  - 霍恩子句：L0 :- L1, . . . , Ln。全部以and连接，只有一个是肯定逻辑，可以转化为条件蕴含形式，使用SAT求解器算法能够快速求解真值

- MulVAL规则定义攻击动作谓词：

  - Exploit rules：execCode(Attacker, Host, Priv) :- vulExists(Host, VulID, Program), vulProperty(VulID, remoteExploit, privEscalation), clientProgram(Host, Program, Priv), malicious(Attacker).
  - Compromise propagation：accessFile(P, H, Access, Path) :- execCode(P, H, Owner), filePath(H, Owner, Path).
  - Multihop network access：netAccess(P, H2, Protocol, Port) :- execCode(P, H1, Priv), hacl(H1, H2, Protocol, Port).

- 额外定义访问规则：

  - allow(Everyone, read, webPages). allow(user, Access, projectPlan). allow(sysAdmin, Access, Data).

- 绑定数据、参与者信息：hasAccount(user, projectPC, userAccount). hasAccount(sysAdmin, webServer, root).

  dataBind(projectPlan,workstation,’/home’). dataBind(webPages, webServer, ’/www’).

- 逻辑编程生成攻击图

## MulVAL存在假设

- 漏洞之间是独立的：好处是，虽然某些软件当前未发现漏洞，但是人们更关注于未来如果存在某个漏洞是否会造成某种损失，这时因为交互规则描述的是一般攻击方法，可以在数据库中模拟存在某个漏洞给出相应的漏洞影响即可进行模拟。坏处，忽略了一些攻击的成本问题，更倾向于关联性高容易实施的攻击，对于给定的权重需要衡量。
- 扫描器需要保证所有主机都提供同时的配置信息，这在某些分布式网络中会出现问题