Set-StrictMode -Version 2.0

function Test-InAuthenticationWindow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][datetime]$Now,
        [Parameter(Mandatory = $true)][timespan]$Start,
        [Parameter(Mandatory = $true)][timespan]$End
    )

    $time = $Now.TimeOfDay
    if ($Start -le $End) {
        return ($time -ge $Start -and $time -le $End)
    }

    return ($time -ge $Start -or $time -le $End)
}

function ConvertFrom-PortalJsonp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content
    )

    $text = $Content.Trim()
    $text = $text.TrimStart([char]0xFEFF)
    $text = $text.Trim()

    if ([string]::IsNullOrWhiteSpace($text)) {
        throw 'Invalid portal response: content is empty.'
    }

    $json = $text
    if (-not ($text.StartsWith('{') -or $text.StartsWith('['))) {
        $match = [regex]::Match(
            $text,
            '^[A-Za-z_$][A-Za-z0-9_$.]*\s*\((?<json>.*)\)\s*;?$',
            [System.Text.RegularExpressions.RegexOptions]::Singleline
        )
        if (-not $match.Success) {
            throw 'Invalid portal response: expected JSON or JSONP.'
        }
        $json = $match.Groups['json'].Value.Trim()
    }

    try {
        return ($json | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        throw "Invalid portal response: JSON parsing failed. $($_.Exception.Message)"
    }
}

function ConvertTo-PortalQueryString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Parameters
    )

    $pairs = foreach ($key in ($Parameters.Keys | Sort-Object)) {
        $name = [System.Uri]::EscapeDataString([string]$key)
        $value = [System.Uri]::EscapeDataString([string]$Parameters[$key])
        "$name=$value"
    }

    return ($pairs -join '&')
}

function Protect-CampusCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Username,
        [Parameter(Mandatory = $true)][securestring]$Password,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path
    )

    Add-Type -AssemblyName System.Security
    $bstr = [IntPtr]::Zero
    $plainPassword = $null
    $plainBytes = $null
    $protectedBytes = $null

    try {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $payload = [ordered]@{
            Version  = 1
            Username = $Username
            Password = $plainPassword
        } | ConvertTo-Json -Compress

        $plainBytes = [Text.Encoding]::UTF8.GetBytes($payload)
        $protectedBytes = [Security.Cryptography.ProtectedData]::Protect(
            $plainBytes,
            $null,
            [Security.Cryptography.DataProtectionScope]::LocalMachine
        )

        $directory = Split-Path -Parent $Path
        if ($directory -and -not (Test-Path -LiteralPath $directory -PathType Container)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        [IO.File]::WriteAllBytes($Path, $protectedBytes)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        if ($null -ne $plainBytes) {
            [Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
        if ($null -ne $protectedBytes) {
            [Array]::Clear($protectedBytes, 0, $protectedBytes.Length)
        }
        $plainPassword = $null
    }
}

function Unprotect-CampusCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Credential file does not exist: $Path"
    }

    Add-Type -AssemblyName System.Security
    $protectedBytes = [IO.File]::ReadAllBytes($Path)
    $plainBytes = $null

    try {
        $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect(
            $protectedBytes,
            $null,
            [Security.Cryptography.DataProtectionScope]::LocalMachine
        )
        $payload = [Text.Encoding]::UTF8.GetString($plainBytes) | ConvertFrom-Json -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace([string]$payload.Username) -or
            [string]::IsNullOrWhiteSpace([string]$payload.Password)) {
            throw 'Credential payload is incomplete.'
        }

        return [pscustomobject]@{
            Username = [string]$payload.Username
            Password = [string]$payload.Password
        }
    }
    catch {
        throw "Credential file could not be decrypted. $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $plainBytes) {
            [Array]::Clear($plainBytes, 0, $plainBytes.Length)
        }
        if ($null -ne $protectedBytes) {
            [Array]::Clear($protectedBytes, 0, $protectedBytes.Length)
        }
    }
}

function Protect-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [string[]]$Secrets = @()
    )

    $safe = $Message
    $safe = [regex]::Replace($safe, '(?i)(https?://[^\s?]+)\?[^\s]+', '$1')
    $safe = [regex]::Replace($safe, '(?i)\b(cookie|set-cookie)\s*:\s*[^\r\n]+', '$1: [REDACTED]')

    foreach ($secret in $Secrets) {
        if (-not [string]::IsNullOrEmpty($secret)) {
            $safe = [regex]::Replace($safe, [regex]::Escape($secret), '[REDACTED]')
        }
    }

    if ($safe.Length -gt 1000) {
        $safe = $safe.Substring(0, 1000) + '...[TRUNCATED]'
    }

    return $safe
}

function Write-CampusLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Level,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Event,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$LogDirectory,
        [string[]]$Secrets = @()
    )

    if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }

    $safeMessage = Protect-LogMessage -Message $Message -Secrets $Secrets
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff zzz')
    $line = '[{0}] [{1}] [{2}] {3}' -f $timestamp, $Level.ToUpperInvariant(), $Event, $safeMessage
    $logPath = Join-Path $LogDirectory ((Get-Date).ToString('yyyy-MM-dd') + '.log')
    Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string[]]$Names,
        $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }

    foreach ($name in $Names) {
        $property = $InputObject.PSObject.Properties[$name]
        if ($null -ne $property -and $null -ne $property.Value -and [string]$property.Value -ne '') {
            return $property.Value
        }
    }

    return $Default
}

function New-PortalCallbackName {
    return ('dr{0}' -f (Get-Random -Minimum 100000 -Maximum 999999))
}

function Assert-PortalUri {
    param([Parameter(Mandatory = $true)][string]$Uri)

    $parsed = [uri]$Uri
    if ($parsed.Scheme -ne 'https' -or $parsed.DnsSafeHost -ne 'p.cpu.edu.cn') {
        throw "Refusing to send a portal request outside https://p.cpu.edu.cn: $($parsed.Scheme)://$($parsed.DnsSafeHost)$($parsed.AbsolutePath)"
    }
}

function Invoke-DefaultPortalRequest {
    param([Parameter(Mandatory = $true)]$Request)

    Assert-PortalUri -Uri ([string]$Request.Uri)
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $response = Invoke-WebRequest `
        -Uri ([string]$Request.Uri) `
        -Method Get `
        -UseBasicParsing `
        -TimeoutSec 10 `
        -Headers @{ 'User-Agent' = 'CPU-CampusNet-AutoAuth/1.0' } `
        -ErrorAction Stop

    return [pscustomobject]@{
        StatusCode = [int]$response.StatusCode
        Content    = [string]$response.Content
    }
}

function Invoke-PortalRequest {
    param(
        [Parameter(Mandatory = $true)]$Request,
        [scriptblock]$RequestInvoker
    )

    Assert-PortalUri -Uri ([string]$Request.Uri)
    if ($null -ne $RequestInvoker) {
        $response = & $RequestInvoker $Request
    }
    else {
        $response = Invoke-DefaultPortalRequest -Request $Request
    }

    if ($null -eq $response) {
        throw 'Portal request returned no response.'
    }

    $statusCode = [int](Get-ObjectPropertyValue -InputObject $response -Names @('StatusCode') -Default 200)
    if ($statusCode -lt 200 -or $statusCode -ge 300) {
        throw "Portal request failed with HTTP status $statusCode."
    }

    return $response
}

function Get-CampusPortalStatus {
    [CmdletBinding()]
    param([scriptblock]$RequestInvoker)

    $parameters = @{
        callback  = New-PortalCallbackName
        jsVersion = '4.2.2'
        v         = Get-Random -Minimum 500 -Maximum 10499
    }
    $uri = 'https://p.cpu.edu.cn/drcom/chkstatus?' + (ConvertTo-PortalQueryString -Parameters $parameters)
    $response = Invoke-PortalRequest -Request ([pscustomobject]@{ Method = 'GET'; Uri = $uri }) -RequestInvoker $RequestInvoker
    $payload = ConvertFrom-PortalJsonp -Content ([string]$response.Content)

    $result = Get-ObjectPropertyValue -InputObject $payload -Names @('result') -Default 0
    $ipv4 = [string](Get-ObjectPropertyValue -InputObject $payload -Names @('v4ip', 'v46ip', 'ss5') -Default '')
    $ipv6 = [string](Get-ObjectPropertyValue -InputObject $payload -Names @('v6ip', 'UserV6IP') -Default '')
    $mac = [string](Get-ObjectPropertyValue -InputObject $payload -Names @('ss4', 'olmac', 'mac') -Default '')
    $mac = $mac -replace '[^0-9A-Fa-f]', ''

    return [pscustomobject]@{
        IsOnline = ([string]$result -eq '1' -or [string]$result -eq 'ok')
        Result    = $result
        IPv4      = $ipv4
        IPv6      = $ipv6
        Mac       = $mac.ToUpperInvariant()
        Raw       = $payload
    }
}

function Get-PortalContext {
    [CmdletBinding()]
    param([scriptblock]$RequestInvoker)

    $rootResponse = Invoke-PortalRequest -Request ([pscustomobject]@{
        Method = 'GET'
        Uri    = 'https://p.cpu.edu.cn/'
    }) -RequestInvoker $RequestInvoker
    $html = [string]$rootResponse.Content
    $status = Get-CampusPortalStatus -RequestInvoker $RequestInvoker

    $scriptMatch = [regex]::Match(
        $html,
        '(?i)eportal/extern/(?<program>[^/]+)/(?<page>[^/]+)/pc(?:_\d+)?\.js'
    )
    $programIndex = if ($scriptMatch.Success) { $scriptMatch.Groups['program'].Value } else { '' }
    $pageIndex = if ($scriptMatch.Success) { $scriptMatch.Groups['page'].Value } else { '' }

    $rootIPv4Match = [regex]::Match($html, '(?is)v4ip\s*=\s*[''"](?<value>[^''"]*)[''"]')
    $rootIPv6Match = [regex]::Match($html, '(?is)v6ip\s*=\s*[''"](?<value>[^''"]*)[''"]')
    $ipv4 = if ($status.IPv4) { $status.IPv4 } elseif ($rootIPv4Match.Success) { $rootIPv4Match.Groups['value'].Value } else { '' }
    $ipv6 = if ($status.IPv6) { $status.IPv6 } elseif ($rootIPv6Match.Success) { $rootIPv6Match.Groups['value'].Value } else { '' }

    $loginMethod = 0
    $ipBytes = [Text.Encoding]::UTF8.GetBytes([string]$ipv4)
    try {
        $configParameters = @{
            callback         = New-PortalCallbackName
            program_index    = $programIndex
            wlan_vlan_id     = 1
            wlan_user_ip     = [Convert]::ToBase64String($ipBytes)
            wlan_user_ipv6   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$ipv6))
            wlan_user_ssid   = ''
            wlan_user_areaid = ''
            wlan_ac_ip       = ''
            wlan_ap_mac      = ''
            gw_id            = ''
            jsVersion        = '4.2.2'
            v                = Get-Random -Minimum 500 -Maximum 10499
        }
        $configUri = 'https://p.cpu.edu.cn:802/eportal/portal/page/loadConfig?' +
            (ConvertTo-PortalQueryString -Parameters $configParameters)
        $configResponse = Invoke-PortalRequest -Request ([pscustomobject]@{ Method = 'GET'; Uri = $configUri }) -RequestInvoker $RequestInvoker
        $config = ConvertFrom-PortalJsonp -Content ([string]$configResponse.Content)
        $configData = Get-ObjectPropertyValue -InputObject $config -Names @('data')
        $loginMethod = [int](Get-ObjectPropertyValue -InputObject $configData -Names @('login_method') -Default 0)
        $programIndex = [string](Get-ObjectPropertyValue -InputObject $configData -Names @('program_index') -Default $programIndex)
        $pageIndex = [string](Get-ObjectPropertyValue -InputObject $configData -Names @('page_index') -Default $pageIndex)
    }
    finally {
        [Array]::Clear($ipBytes, 0, $ipBytes.Length)
    }

    $captchaElement = [regex]::Match(
        $html,
        '(?is)<input[^>]+name\s*=\s*[''"]captcha[''"][^>]*>'
    )
    $captchaRequired = $captchaElement.Success -and $captchaElement.Value -notmatch '(?i)display\s*:\s*none'
    $dataEncryptionRequired = $html -match '(?is)page_data_encrypt\s*=\s*[''"]1[''"]'

    $raw = $status.Raw
    return [pscustomobject]@{
        Adapter               = if ($loginMethod -eq 0) { 'DrCom' } else { 'EPortal' }
        LoginMethod           = $loginMethod
        IPv4                  = [string]$ipv4
        IPv6                  = [string]$ipv6
        Mac                   = [string]$status.Mac
        Vlan                  = [int](Get-ObjectPropertyValue -InputObject $raw -Names @('vlanid', 'vlan') -Default 1)
        AcIp                  = [string](Get-ObjectPropertyValue -InputObject $raw -Names @('wlanacip', 'acip') -Default '')
        AcName                = [string](Get-ObjectPropertyValue -InputObject $raw -Names @('wlanacname', 'acname') -Default '')
        ProgramIndex          = $programIndex
        PageIndex             = $pageIndex
        CaptchaRequired       = [bool]$captchaRequired
        DataEncryptionRequired = [bool]$dataEncryptionRequired
    }
}

function New-DrComLoginRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Credential,
        [Parameter(Mandatory = $true)]$Context
    )

    $parameters = @{
        DDDDD         = [string]$Credential.Username
        upass         = [string]$Credential.Password
        '0MKKey'      = 123456
        R1            = 0
        R2            = 0
        R3            = 0
        R6            = 0
        para          = '00'
        v4ip          = [string]$Context.IPv4
        v6ip          = [string]$Context.IPv6
        terminal_type = 1
        lang          = 'zh'
        callback      = New-PortalCallbackName
        jsVersion     = '4.2.2'
        v             = Get-Random -Minimum 500 -Maximum 10499
    }
    $uri = 'https://p.cpu.edu.cn/drcom/login?' + (ConvertTo-PortalQueryString -Parameters $parameters)

    return [pscustomobject]@{ Method = 'GET'; Uri = $uri; Adapter = 'DrCom' }
}

function New-EPortalLoginRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Credential,
        [Parameter(Mandatory = $true)]$Context
    )

    $parameters = @{
        login_method   = [int]$Context.LoginMethod
        user_account   = [string]$Credential.Username
        user_password  = [string]$Credential.Password
        wlan_user_ip   = [string]$Context.IPv4
        wlan_user_ipv6 = [string]$Context.IPv6
        wlan_user_mac  = [string]$Context.Mac
        wlan_vlan_id   = [int](Get-ObjectPropertyValue -InputObject $Context -Names @('Vlan') -Default 1)
        wlan_ac_ip     = [string](Get-ObjectPropertyValue -InputObject $Context -Names @('AcIp') -Default '')
        wlan_ac_name   = [string](Get-ObjectPropertyValue -InputObject $Context -Names @('AcName') -Default '')
        terminal_type  = 1
        lang           = 'zh'
        callback       = New-PortalCallbackName
        jsVersion      = '4.2.2'
        v              = Get-Random -Minimum 500 -Maximum 10499
    }
    $uri = 'https://p.cpu.edu.cn:802/eportal/portal/login?' + (ConvertTo-PortalQueryString -Parameters $parameters)

    return [pscustomobject]@{ Method = 'GET'; Uri = $uri; Adapter = 'EPortal' }
}

function Invoke-CampusPortalLogin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Credential,
        [Parameter(Mandatory = $true)]$Context,
        [scriptblock]$RequestInvoker
    )

    if ([bool]$Context.CaptchaRequired) {
        throw 'CAPTCHA is enabled; automatic login is intentionally disabled.'
    }
    if ([bool]$Context.DataEncryptionRequired) {
        throw 'Portal request encryption is enabled; this configuration is not supported safely.'
    }

    $request = if ([string]$Context.Adapter -eq 'EPortal') {
        New-EPortalLoginRequest -Credential $Credential -Context $Context
    }
    else {
        New-DrComLoginRequest -Credential $Credential -Context $Context
    }

    $response = Invoke-PortalRequest -Request $request -RequestInvoker $RequestInvoker
    $payload = ConvertFrom-PortalJsonp -Content ([string]$response.Content)
    $result = Get-ObjectPropertyValue -InputObject $payload -Names @('result') -Default 0
    $message = [string](Get-ObjectPropertyValue -InputObject $payload -Names @('msg', 'message', 'error') -Default '')

    return [pscustomobject]@{
        Success = ([string]$result -eq '1' -or [string]$result -eq 'ok')
        Result  = $result
        Message = $message
        Adapter = [string]$request.Adapter
    }
}

function Invoke-AuthenticationWindow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][datetime]$StartDate,
        [Parameter(Mandatory = $true)][timespan]$WindowStart,
        [Parameter(Mandatory = $true)][timespan]$WindowEnd,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$IntervalSeconds,
        [ValidateRange(30, 3600)][int]$PolicyBackoffSeconds = 120,
        [Parameter(Mandatory = $true)][scriptblock]$NowProvider,
        [Parameter(Mandatory = $true)][scriptblock]$SleepAction,
        [Parameter(Mandatory = $true)][scriptblock]$StatusAction,
        [Parameter(Mandatory = $true)][scriptblock]$LoginAction,
        [Parameter(Mandatory = $true)][scriptblock]$LogAction
    )

    $windowStartDate = $StartDate.Date.Add($WindowStart)
    $windowEndDate = $StartDate.Date.Add($WindowEnd)
    if ($WindowEnd -lt $WindowStart) {
        $windowEndDate = $windowEndDate.AddDays(1)
    }
    $windowEndExclusive = $windowEndDate.AddSeconds(1)

    $checks = 0
    $loginAttempts = 0
    $nextLoginAllowedAt = [datetime]::MinValue
    $now = [datetime](& $NowProvider)

    if ($now -lt $windowStartDate) {
        $waitSeconds = [Math]::Ceiling(($windowStartDate - $now).TotalSeconds)
        if ($waitSeconds -gt 0) {
            & $SleepAction $waitSeconds
        }
        $now = [datetime](& $NowProvider)
    }

    if ($now -ge $windowEndExclusive) {
        & $LogAction 'INFO' 'MissedWindow' 'The authentication window has already ended.'
        return [pscustomobject]@{
            Checks        = 0
            LoginAttempts = 0
            ExitReason    = 'MissedWindow'
        }
    }

    while ($now -lt $windowEndExclusive) {
        $iterationStart = $now
        $checks++

        try {
            $status = & $StatusAction
            $isOnline = [bool](Get-ObjectPropertyValue -InputObject $status -Names @('IsOnline') -Default $false)

            if ($isOnline) {
                $nextLoginAllowedAt = [datetime]::MinValue
                & $LogAction 'INFO' 'Online' 'Campus network authentication is active.'
            }
            else {
                if ($iterationStart -lt $nextLoginAllowedAt) {
                    & $LogAction 'WARN' 'Offline' 'Campus network is offline; portal time-policy backoff is active.'
                    & $LogAction 'INFO' 'PolicyBackoff' (
                        'Status checks continue every {0} seconds; next login attempt is allowed at {1:HH:mm:ss}.' -f
                        $IntervalSeconds,
                        $nextLoginAllowedAt
                    )
                }
                else {
                    & $LogAction 'WARN' 'Offline' 'Campus network is offline; attempting authentication.'
                    $loginAttempts++
                    $loginResult = & $LoginAction
                    $loginSucceeded = [bool](Get-ObjectPropertyValue -InputObject $loginResult -Names @('Success') -Default $false)
                    $loginMessage = [string](Get-ObjectPropertyValue -InputObject $loginResult -Names @('Message') -Default '')
                    if ($loginSucceeded) {
                        $nextLoginAllowedAt = [datetime]::MinValue
                        & $LogAction 'INFO' 'LoginSucceeded' $loginMessage
                    }
                    else {
                        & $LogAction 'ERROR' 'LoginFailed' $loginMessage
                        if ($loginMessage -match '(?i)时间策略|本时段.*不允许上网|not allowed.*(?:time|period)') {
                            $nextLoginAllowedAt = $iterationStart.AddSeconds($PolicyBackoffSeconds)
                            & $LogAction 'WARN' 'PolicyBackoff' (
                                'Portal time policy refused login; pausing login submissions for {0} seconds, until {1:HH:mm:ss}.' -f
                                $PolicyBackoffSeconds,
                                $nextLoginAllowedAt
                            )
                        }
                    }
                }
            }
        }
        catch {
            & $LogAction 'ERROR' 'CheckFailed' $_.Exception.Message
        }

        $afterAction = [datetime](& $NowProvider)
        $elapsedSeconds = [Math]::Max(0, ($afterAction - $windowStartDate).TotalSeconds)
        $nextSlotIndex = [Math]::Floor($elapsedSeconds / $IntervalSeconds) + 1
        $nextAttempt = $windowStartDate.AddSeconds($nextSlotIndex * $IntervalSeconds)
        if ($nextAttempt -gt $windowEndDate) {
            break
        }

        $sleepSeconds = [Math]::Ceiling(($nextAttempt - $afterAction).TotalSeconds)
        if ($sleepSeconds -gt 0) {
            & $SleepAction $sleepSeconds
        }
        $now = [datetime](& $NowProvider)
    }

    return [pscustomobject]@{
        Checks        = $checks
        LoginAttempts = $loginAttempts
        ExitReason    = 'WindowComplete'
    }
}

function Invoke-CampusCredentialInitializer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ScriptPath,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$CredentialPath
    )

    if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
        throw "Credential initializer does not exist: $ScriptPath"
    }

    & $ScriptPath -CredentialPath $CredentialPath
    $invocationSucceeded = $?
    if (-not $invocationSucceeded) {
        throw 'Credential initialization script reported a failure.'
    }
}

function Get-CampusScheduledTaskSpec {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$InstallDirectory
    )

    $scriptPath = Join-Path $InstallDirectory 'CampusNetAuth.ps1'
    $powerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

    return [pscustomobject]@{
        TaskName          = 'CPU-CampusNet-AutoAuth'
        Description       = 'Checks CPU campus network authentication every 30 seconds from 03:58 through 05:00, with a two-minute backoff after a portal time-policy refusal.'
        Executable        = $powerShellPath
        Arguments         = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -WindowStart "03:58:00" -WindowEnd "05:00:00" -IntervalSeconds 30 -PolicyBackoffSeconds 120' -f $scriptPath
        DailyAt           = [timespan]::Parse('03:58:00')
        WindowStart       = [timespan]::Parse('03:58:00')
        WindowEnd         = [timespan]::Parse('05:00:00')
        IntervalSeconds   = 30
        PolicyBackoffSeconds = 120
        UserId            = 'SYSTEM'
        LogonType         = 'ServiceAccount'
        RunLevel          = 'Highest'
        MultipleInstances = 'IgnoreNew'
        StartWhenAvailable = $true
        ExecutionTimeLimit = [timespan]::FromMinutes(70)
    }
}

function Test-CampusInstallSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SourceDirectory
    )

    $requiredFiles = @(
        'CampusNetAuth.Core.psm1',
        'CampusNetAuth.ps1',
        'Initialize-CampusNetCredential.ps1',
        'Uninstall-CampusNetAutoAuth.ps1'
    )

    foreach ($name in $requiredFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $SourceDirectory $name) -PathType Leaf)) {
            return $false
        }
    }

    return $true
}

function New-CampusInstallSecurityDescriptor {
    [CmdletBinding()]
    param()

    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)

    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $fullControl = [Security.AccessControl.FileSystemRights]::FullControl

    foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidValue)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            $fullControl,
            $inheritance,
            $propagation,
            $allow
        )
        [void]$acl.AddAccessRule($rule)
    }

    return $acl
}

function Set-CampusInstallAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$InstallDirectory
    )

    if (-not (Test-Path -LiteralPath $InstallDirectory -PathType Container)) {
        throw "Install directory does not exist: $InstallDirectory"
    }

    $acl = New-CampusInstallSecurityDescriptor
    Set-Acl -LiteralPath $InstallDirectory -AclObject $acl -ErrorAction Stop
}

Export-ModuleMember -Function @(
    'Test-InAuthenticationWindow',
    'ConvertFrom-PortalJsonp',
    'ConvertTo-PortalQueryString',
    'Protect-CampusCredential',
    'Unprotect-CampusCredential',
    'Protect-LogMessage',
    'Write-CampusLog',
    'Get-CampusPortalStatus',
    'Get-PortalContext',
    'New-DrComLoginRequest',
    'New-EPortalLoginRequest',
    'Invoke-CampusPortalLogin',
    'Invoke-AuthenticationWindow',
    'Invoke-CampusCredentialInitializer',
    'Get-CampusScheduledTaskSpec',
    'Test-CampusInstallSource',
    'New-CampusInstallSecurityDescriptor',
    'Set-CampusInstallAcl'
)
