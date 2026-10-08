[CmdletBinding()]
param(
    [string]$CredentialPath,
    [string]$LogDirectory,
    [timespan]$WindowStart = ([timespan]::Parse('03:58:00')),
    [timespan]$WindowEnd = ([timespan]::Parse('05:00:00')),
    [ValidateRange(1, 3600)][int]$IntervalSeconds = 30,
    [ValidateRange(30, 3600)][int]$PolicyBackoffSeconds = 120
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($CredentialPath)) {
    $CredentialPath = Join-Path $PSScriptRoot 'credential.bin'
}
if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
    $LogDirectory = Join-Path $PSScriptRoot 'logs'
}

$modulePath = Join-Path $PSScriptRoot 'CampusNetAuth.Core.psm1'
Import-Module -Name $modulePath -Force -ErrorAction Stop

$credential = $null
$secrets = @()

try {
    $credential = Unprotect-CampusCredential -Path $CredentialPath
    $secrets = @([string]$credential.Username, [string]$credential.Password)
}
catch {
    try {
        Write-CampusLog `
            -Level 'ERROR' `
            -Event 'CredentialUnavailable' `
            -Message $_.Exception.Message `
            -LogDirectory $LogDirectory
    }
    catch {
        Write-Error 'Campus network credential is unavailable and the error log could not be written.'
    }
    exit 2
}

try {
    if (Test-Path -LiteralPath $LogDirectory -PathType Container) {
        $cutoff = (Get-Date).AddDays(-14)
        Get-ChildItem -LiteralPath $LogDirectory -Filter '*.log' -File -ErrorAction Stop |
            Where-Object { $_.LastWriteTime -lt $cutoff } |
            Remove-Item -Force -ErrorAction Stop
    }
}
catch {
    Write-CampusLog `
        -Level 'WARN' `
        -Event 'LogCleanupFailed' `
        -Message $_.Exception.Message `
        -LogDirectory $LogDirectory `
        -Secrets $secrets
}

$nowProvider = { Get-Date }
$sleepAction = {
    param($seconds)
    if ([double]$seconds -gt 0) {
        Start-Sleep -Seconds ([double]$seconds)
    }
}
$statusAction = { Get-CampusPortalStatus }
$loginAction = {
    $context = Get-PortalContext
    Invoke-CampusPortalLogin -Credential $credential -Context $context
}.GetNewClosure()
$logAction = {
    param($level, $event, $message)
    Write-CampusLog `
        -Level $level `
        -Event $event `
        -Message ([string]$message) `
        -LogDirectory $LogDirectory `
        -Secrets $secrets
}.GetNewClosure()

try {
    $summary = Invoke-AuthenticationWindow `
        -StartDate (Get-Date) `
        -WindowStart $WindowStart `
        -WindowEnd $WindowEnd `
        -IntervalSeconds $IntervalSeconds `
        -PolicyBackoffSeconds $PolicyBackoffSeconds `
        -NowProvider $nowProvider `
        -SleepAction $sleepAction `
        -StatusAction $statusAction `
        -LoginAction $loginAction `
        -LogAction $logAction

    & $logAction 'INFO' 'WindowFinished' (
        'Checks={0}; LoginAttempts={1}; ExitReason={2}' -f
        $summary.Checks,
        $summary.LoginAttempts,
        $summary.ExitReason
    )
    exit 0
}
catch {
    try {
        & $logAction 'ERROR' 'FatalError' $_.Exception.Message
    }
    catch {
        Write-Error 'Campus network authentication failed and the error log could not be written.'
    }
    exit 1
}
finally {
    $credential = $null
    $secrets = @()
}
