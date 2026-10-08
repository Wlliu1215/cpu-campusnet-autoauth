[CmdletBinding()]
param(
    [string]$CredentialPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($CredentialPath)) {
    $CredentialPath = Join-Path $PSScriptRoot 'credential.bin'
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    $powerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -CredentialPath "{1}"' -f
        $PSCommandPath,
        $CredentialPath
    $process = Start-Process -FilePath $powerShellPath -Verb RunAs -ArgumentList $arguments -Wait -PassThru
    exit $process.ExitCode
}

$modulePath = Join-Path $PSScriptRoot 'CampusNetAuth.Core.psm1'
Import-Module -Name $modulePath -Force -ErrorAction Stop

do {
    $username = (Read-Host '请输入校园网学号').Trim()
} while ([string]::IsNullOrWhiteSpace($username))

$password = $null
$confirmation = $null
$plainPassword = $null
$plainConfirmation = $null
$passwordBstr = [IntPtr]::Zero
$confirmationBstr = [IntPtr]::Zero

try {
    while ($true) {
        if ($null -ne $password) {
            $password.Dispose()
            $password = $null
        }
        if ($null -ne $confirmation) {
            $confirmation.Dispose()
            $confirmation = $null
        }

        $password = Read-Host '请输入校园网密码' -AsSecureString
        $confirmation = Read-Host '请再次输入校园网密码' -AsSecureString

        try {
            $passwordBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
            $confirmationBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmation)
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordBstr)
            $plainConfirmation = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($confirmationBstr)

            if ([string]::IsNullOrEmpty($plainPassword)) {
                Write-Warning '密码不能为空，请重新输入。'
                continue
            }
            if ($plainPassword -ne $plainConfirmation) {
                Write-Warning '两次输入的密码不一致，请重新输入。'
                continue
            }
            break
        }
        finally {
            if ($passwordBstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordBstr)
                $passwordBstr = [IntPtr]::Zero
            }
            if ($confirmationBstr -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($confirmationBstr)
                $confirmationBstr = [IntPtr]::Zero
            }
            $plainPassword = $null
            $plainConfirmation = $null
        }
    }

    Protect-CampusCredential -Username $username -Password $password -Path $CredentialPath
    Write-Host "加密凭据已保存到：$CredentialPath"
}
finally {
    if ($null -ne $password) {
        $password.Dispose()
    }
    if ($null -ne $confirmation) {
        $confirmation.Dispose()
    }
}
