[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$SkipCredentialInitialization
)

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
    [void]$PSCmdlet.ShouldProcess($installDirectory, 'Install campus network auto-authentication and register its scheduled task')
    Write-Host 'WhatIf: no files, credentials, ACLs, or scheduled tasks were changed.'
    return
}

if (-not (Test-IsAdministrator)) {
    $powerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath
    if ($SkipCredentialInitialization) {
        $arguments += ' -SkipCredentialInitialization'
    }
    $process = Start-Process -FilePath $powerShellPath -Verb RunAs -ArgumentList $arguments -Wait -PassThru
    exit $process.ExitCode
}

$sourceModulePath = Join-Path $PSScriptRoot 'CampusNetAuth.Core.psm1'
Import-Module -Name $sourceModulePath -Force -ErrorAction Stop

if (-not (Test-CampusInstallSource -SourceDirectory $PSScriptRoot)) {
    throw '安装源文件不完整。请确保所有脚本位于同一目录后重试。'
}

if ($PSCmdlet.ShouldProcess($installDirectory, 'Create or update the installation directory')) {
    New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null

    $runtimeFiles = @(
        'CampusNetAuth.Core.psm1',
        'CampusNetAuth.ps1',
        'Initialize-CampusNetCredential.ps1',
        'Uninstall-CampusNetAutoAuth.ps1',
        'README.md'
    )
    foreach ($name in $runtimeFiles) {
        $sourcePath = Join-Path $PSScriptRoot $name
        if (Test-Path -LiteralPath $sourcePath -PathType Leaf) {
            Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $installDirectory $name) -Force
        }
    }
    Set-CampusInstallAcl -InstallDirectory $installDirectory
}

$installedModulePath = Join-Path $installDirectory 'CampusNetAuth.Core.psm1'
Import-Module -Name $installedModulePath -Force -ErrorAction Stop

$credentialPath = Join-Path $installDirectory 'credential.bin'
if ($SkipCredentialInitialization) {
    if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {
        throw '指定了 SkipCredentialInitialization，但安装目录中不存在凭据文件。'
    }
}
else {
    $initializeCredential = $true
    if (Test-Path -LiteralPath $credentialPath -PathType Leaf) {
        $answer = Read-Host '检测到现有加密凭据。是否重新录入？[y/N]'
        $initializeCredential = $answer -match '^(?i:y|yes|是)$'
    }
    if ($initializeCredential) {
        Invoke-CampusCredentialInitializer `
            -ScriptPath (Join-Path $installDirectory 'Initialize-CampusNetCredential.ps1') `
            -CredentialPath $credentialPath
    }
}

$taskSpec = Get-CampusScheduledTaskSpec -InstallDirectory $installDirectory
if ($PSCmdlet.ShouldProcess($taskName, 'Register or update the SYSTEM scheduled task')) {
    Import-Module ScheduledTasks -ErrorAction Stop
    $action = New-ScheduledTaskAction -Execute $taskSpec.Executable -Argument $taskSpec.Arguments
    $trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.Add($taskSpec.DailyAt))
    $principal = New-ScheduledTaskPrincipal `
        -UserId $taskSpec.UserId `
        -LogonType $taskSpec.LogonType `
        -RunLevel $taskSpec.RunLevel
    $settings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -MultipleInstances $taskSpec.MultipleInstances `
        -ExecutionTimeLimit $taskSpec.ExecutionTimeLimit `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    Register-ScheduledTask `
        -TaskName $taskSpec.TaskName `
        -Description $taskSpec.Description `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Force | Out-Null
}

$taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
Write-Host "安装目录：$installDirectory"
Write-Host "计划任务：$taskName"
Write-Host "下次运行：$($taskInfo.NextRunTime)"
Write-Host '安装完成；本次安装没有立即访问或重新认证校园网。'
