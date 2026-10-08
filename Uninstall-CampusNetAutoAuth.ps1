[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$installDirectory = Join-Path $env:ProgramData 'CPU-CampusNet-AutoAuth'
$taskName = 'CPU-CampusNet-AutoAuth'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($WhatIfPreference) {
    [void]$PSCmdlet.ShouldProcess($taskName, 'Stop and unregister the scheduled task')
    [void]$PSCmdlet.ShouldProcess($installDirectory, 'Delete the installation directory, encrypted credential, and logs')
    Write-Host 'WhatIf: no scheduled tasks or files were changed.'
    return
}

if (-not (Test-IsAdministrator)) {
    $powerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath
    $process = Start-Process -FilePath $powerShellPath -Verb RunAs -ArgumentList $arguments -Wait -PassThru
    exit $process.ExitCode
}

Import-Module ScheduledTasks -ErrorAction Stop
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -ne $task -and $PSCmdlet.ShouldProcess($taskName, 'Stop and unregister the scheduled task')) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
}

$expectedDirectory = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'CPU-CampusNet-AutoAuth'))
$resolvedTarget = [IO.Path]::GetFullPath($installDirectory)
if ($resolvedTarget -ne $expectedDirectory) {
    throw "拒绝删除非预期目录：$resolvedTarget"
}

if ((Test-Path -LiteralPath $resolvedTarget) -and
    $PSCmdlet.ShouldProcess($resolvedTarget, 'Delete the installation directory, encrypted credential, and logs')) {
    Remove-Item -LiteralPath $resolvedTarget -Recurse -Force -ErrorAction Stop
}

Write-Host '校园网自动认证任务及其本地文件已卸载；当前网络会话未被修改。'
