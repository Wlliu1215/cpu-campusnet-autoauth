# 中国药科大学校园网定时自动认证

这组 PowerShell 脚本用于中国药科大学实验室 Windows 电脑，目标门户固定为 [`https://p.cpu.edu.cn/`](https://p.cpu.edu.cn/)。每天 **03:58:00–05:00:00** 之间每 **30 秒**检查一次校园网状态。在线时只检查；掉线时才使用该电脑本地加密保存的学号和密码重新认证。若门户明确返回“本时段不允许上网”，状态检查仍保持每 30 秒一次，登录提交暂缓 2 分钟。

这是非官方工具，只适用于当前门户协议；不能绕过学校设置的上网时段、验证码或其他访问限制。实验室每台电脑应分别安装并录入自己的校园网凭据。**同一台电脑的安装目录只保存一组凭据**，后续重新录入会替换该组凭据。

项目代码采用 [MIT License](LICENSE)。

## 运行要求

- Windows 10 或 Windows 11
- Windows PowerShell 5.1
- 安装和卸载时具有本机管理员权限
- 电脑时间、时区正确
- 电脑在检查时段保持开机、唤醒，并连接校园网网线或 Wi-Fi
- 学校允许该电脑使用网页登录认证

脚本不会绕过验证码、短信验证、多因素认证或 TLS 证书错误。学校如果启用这些交互，任务会记录错误并停止该轮提交。

## 一键安装

从 GitHub 下载源码 ZIP 并解压到本地文件夹，或克隆仓库。在解压后的项目目录打开 PowerShell，运行：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Install-CampusNetAutoAuth.ps1
```

安装过程会：

1. 如有需要，弹出 Windows UAC 管理员确认。
2. 将运行文件复制到 `C:\ProgramData\CPU-CampusNet-AutoAuth`。
3. 将目录权限限制为 `SYSTEM` 和本机 Administrators。
4. 在本机提示输入该电脑使用的学号、密码和确认密码。
5. 使用 Windows DPAPI LocalMachine 加密凭据。
6. 注册名为 `CPU-CampusNet-AutoAuth` 的 SYSTEM 计划任务。

安装不会立即访问或重新认证校园网。任务每天 03:58 启动，以 SYSTEM 和最高权限运行，最长运行 70 分钟；同一任务已有实例时不会再启动第二个实例。

可以先预览安装动作，不修改系统：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Install-CampusNetAutoAuth.ps1 -WhatIf
```

重复运行安装脚本会更新文件和任务定义，不会创建重复任务。如果已有凭据，安装程序会询问是否重新录入。

仅更新程序和计划任务、保留已经录入的凭据时，在项目目录运行：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Install-CampusNetAutoAuth.ps1 -SkipCredentialInitialization
```

这个参数要求该电脑已安装且 `credential.bin` 仍在安装目录。不要把加密凭据文件从别的电脑复制过来；每台电脑都需要本机初始化。

## 时间行为

- 03:58:00：立即执行第一次状态检查。
- 在线时：不提交登录，但 30 秒后继续检查。
- 离线时：重新读取当轮 IP 和门户配置，然后尝试一次认证。
- 普通超时或失败：等待到下一个固定的半分钟刻度再试。
- 门户明确返回时间策略拒绝：继续每 30 秒检查状态，但 2 分钟内不再提交登录；到期后若仍离线再试一次。
- 如果任务晚几秒启动，会先立即检查一次，随后回到 `:00`、`:30` 的固定刻度，不会因启动延迟漏掉窗口末端。
- 05:00:00：允许执行最后一次检查；系统唤醒晚于整秒但仍在这一秒内时，也会完成这次检查，随后退出。
- 电脑在 03:58 后恢复运行：只要仍未超过 05:00，就执行剩余窗口。
- 电脑在 05:00 后恢复运行：当天不补做认证。

## 现场测试自动重连

在电脑现场打开**管理员 PowerShell**，按顺序逐行执行下面三行。第三行会启动一个 3 分钟的检查窗口；如果检测到掉线，会真实提交认证请求。

```powershell
$start = (Get-Date).ToString('HH:mm:ss')
$end = (Get-Date).AddMinutes(3).ToString('HH:mm:ss')
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "$env:ProgramData\CPU-CampusNet-AutoAuth\CampusNetAuth.ps1" -WindowStart $start -WindowEnd $end -IntervalSeconds 30
```

启动命令后，在校园网认证网页点击“注销”，等待下一轮检查。保持网线、Wi-Fi 和网卡连接；拔网线或禁用网卡后，脚本无法自行恢复物理连接。测试成功时日志会依次出现 `Offline`、`LoginSucceeded`、`Online`。如果远程控制依赖这条网络连接，请在电脑现场测试。

## 更新学号或密码

以管理员 PowerShell 运行：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "$env:ProgramData\CPU-CampusNet-AutoAuth\Initialize-CampusNetCredential.ps1"
```

计划任务命令行、配置文件和日志均不包含明文密码。凭据使用机器级 DPAPI 加密，并通过 ACL 限制访问；本机 SYSTEM 和本机管理员属于信任边界。凭据文件保存在 `C:\ProgramData\CPU-CampusNet-AutoAuth\credential.bin`，不属于项目源码，不要提交到 GitHub 或发送给他人。

门户协议会通过 HTTPS 请求的查询参数传递密码。脚本不记录完整请求 URL，但使用代理软件时应让 `p.cpu.edu.cn` 直连，避免把认证请求发送到不可信代理。

## 日志

日志目录：

```text
C:\ProgramData\CPU-CampusNet-AutoAuth\logs
```

每天一个 UTF-8 日志文件，只记录时间、事件类型和脱敏结果。脚本不会记录完整请求 URL、Cookie、完整门户响应、学号或密码。启动时会删除 14 天以前的日志。

在管理员 PowerShell 中查看当天最新记录：

```powershell
Get-Content "$env:ProgramData\CPU-CampusNet-AutoAuth\logs\$(Get-Date -Format 'yyyy-MM-dd').log" -Tail 50
```

常见事件：

- `Online`：当前已认证。
- `Offline`：检测到掉线，准备认证。
- `LoginSucceeded`：门户明确返回认证成功。
- `LoginFailed`：门户明确返回认证失败。
- `PolicyBackoff`：门户按时间策略拒绝登录；状态检查继续，登录提交暂缓 2 分钟。
- `CheckFailed`：本轮网络、解析、验证码或门户调用异常。
- `CredentialUnavailable`：凭据不存在或无法在本机解密，当天任务终止。
- `WindowFinished`：当天检查窗口结束。

## 查看任务状态

在管理员 PowerShell 中运行：

```powershell
Get-ScheduledTask -TaskName 'CPU-CampusNet-AutoAuth'
Get-ScheduledTaskInfo -TaskName 'CPU-CampusNet-AutoAuth'
(Get-ScheduledTask -TaskName 'CPU-CampusNet-AutoAuth').Actions.Arguments
(Get-ScheduledTask -TaskName 'CPU-CampusNet-AutoAuth').Settings.ExecutionTimeLimit
```

重点查看 `State`、`LastRunTime`、`LastTaskResult` 和 `NextRunTime`。任务参数应包含 `-WindowEnd "05:00:00"`；执行时限 `PT1H10M` 表示 70 分钟。

## 本地自动测试

测试不会访问真实门户、不会创建计划任务，也不会要求真实学号或密码：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
```

## 故障排查

### 一直显示 Online，但远程软件仍断线

校园网认证可能已经恢复，而远程控制软件自身没有作为服务运行。确认远程控制软件已设置为开机启动、无人值守，并在 Windows 锁屏状态下仍可运行。

### CheckFailed：CAPTCHA

学校启用了验证码。脚本会按设计拒绝绕过，需要联系学校信息化部门或改用其正式客户端/允许的认证方式。

### CheckFailed：证书或 TLS

脚本不会忽略证书错误。检查电脑时间、学校证书和认证地址，不要添加跳过证书验证的参数。

### CredentialUnavailable

凭据文件缺失、损坏，或从另一台电脑复制而来。重新运行凭据初始化工具；DPAPI LocalMachine 凭据不能跨电脑复制使用。

### 门户返回“本时段不允许上网”

这是学校门户返回的时间策略拒绝。脚本每 30 秒继续检测，并按 2 分钟退避再次尝试登录，直到 05:00；如果学校仍未开放，脚本无法越过该限制。请向学校确认允许上网的时段。

### 认证网页打不开或 CheckFailed：操作超时

先确认电脑仍连着校园网。如果使用代理或 TUN，检查 `p.cpu.edu.cn` 是否被设置为直连；可在本机用 `curl.exe --noproxy "*" -I https://p.cpu.edu.cn/` 做不含凭据的连通性检查。

### 门户升级后认证失败

查看脱敏日志。脚本支持当前 Dr.COM `/drcom/login` 和 ePortal `/eportal/portal/login` 两种流程；如果学校改变接口或启用请求加密，需要更新脚本，不能盲目重复提交。

## 卸载

在本目录或安装目录运行：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-CampusNetAutoAuth.ps1
```

卸载会停止并删除计划任务，并删除安装目录、加密凭据和日志。它不会注销当前校园网会话，也不会修改网卡、防火墙或远程控制软件设置。

可以先预览：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-CampusNetAutoAuth.ps1 -WhatIf
```
