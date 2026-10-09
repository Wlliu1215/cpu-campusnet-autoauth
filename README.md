# CPU 校园网自动认证

用于需要保持远程可访问的实验室 Windows 电脑。每天 **03:58–04:28** 每 **30 秒**检查一次 CPU 校园网状态；只有掉线时才尝试通过 [认证门户](https://p.cpu.edu.cn/)重新登录。电脑须在该时段开机、未休眠并连接校园网。本项目为非官方工具，不能绕过门户的时间限制或验证码。

## 安装与更新

下载仓库 ZIP 并解压，在项目目录打开 PowerShell，运行：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Install-CampusNetAutoAuth.ps1
```

按提示确认管理员权限，并在本机输入该电脑使用的学号和密码。安装程序会复制脚本、加密保存凭据并注册 `CPU-CampusNet-AutoAuth` 计划任务；**安装不会立即登录**。任务以 `SYSTEM` 身份运行，不需要保持 PowerShell 窗口开启。

已有凭据、只想更新脚本及计划任务时运行：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Install-CampusNetAutoAuth.ps1 -SkipCredentialInitialization
```

从 GitHub 下载新代码后，**必须重新运行安装命令**，已安装的计划任务才会采用新时间。管理员 PowerShell 可用 `Get-ScheduledTask -TaskName 'CPU-CampusNet-AutoAuth'` 查看任务；平时显示 `Ready` 属正常状态。

## 测试与日志

项目自带的测试不访问真实门户：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
```

要测试掉线后自动重连，请**在电脑现场**用管理员 PowerShell 逐行运行下列命令，再从认证页面注销；不要通过依赖这条网络的远程连接测试。

```powershell
$start = (Get-Date).ToString('HH:mm:ss')
$end = (Get-Date).AddMinutes(3).ToString('HH:mm:ss')
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "$env:ProgramData\CPU-CampusNet-AutoAuth\CampusNetAuth.ps1" -WindowStart $start -WindowEnd $end -IntervalSeconds 30
```

查看当天日志（`Offline → LoginSucceeded → Online` 表示重连成功）：

```powershell
Get-Content "$env:ProgramData\CPU-CampusNet-AutoAuth\logs\$(Get-Date -Format 'yyyy-MM-dd').log" -Tail 30
```

## 卸载

在项目目录运行以下命令。卸载会删除计划任务、安装目录、本机加密凭据和日志：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-CampusNetAutoAuth.ps1
```

## 实现原理

Windows 计划任务每天 03:58 启动脚本，到 04:28 结束。脚本查询门户状态，在线时只检查；离线时读取当前网络信息并提交认证。门户按时间策略拒绝时，仍每 30 秒检查状态，但登录提交暂缓 2 分钟。凭据仅在本机用 DPAPI 加密保存，安装目录限制为管理员和 `SYSTEM` 可访问；不要上传 `credential.bin` 或日志。代理/TUN 软件应让 `p.cpu.edu.cn` 直连。

项目采用 [MIT License](LICENSE)。
