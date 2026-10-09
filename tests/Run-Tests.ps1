[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:Passed = 0
$script:Failed = 0

function Invoke-Test {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    try {
        & $Body
        $script:Passed++
        Write-Host "[PASS] $Name"
    }
    catch {
        $script:Failed++
        Write-Host "[FAIL] $Name"
        Write-Host "       $($_.Exception.Message)"
        if ($_.ScriptStackTrace) {
            Write-Host "       $($_.ScriptStackTrace -replace "`r?`n", "`n       ")"
        }
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message = 'Expected true.')
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-False {
    param([bool]$Condition, [string]$Message = 'Expected false.')
    if ($Condition) {
        throw $Message
    }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Message = '')
    if ($Expected -ne $Actual) {
        if ([string]::IsNullOrWhiteSpace($Message)) {
            $Message = "Expected <$Expected>, got <$Actual>."
        }
        throw $Message
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [string]$MessagePattern = ''
    )

    $caught = $null
    try {
        & $Body
    }
    catch {
        $caught = $_
    }

    if ($null -eq $caught) {
        throw 'Expected an exception, but none was thrown.'
    }

    if ($MessagePattern -and $caught.Exception.Message -notmatch $MessagePattern) {
        throw "Exception message <$($caught.Exception.Message)> did not match <$MessagePattern>."
    }
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $projectRoot 'CampusNetAuth.Core.psm1'

if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    Write-Host "[FAIL] Core module exists: $modulePath"
    exit 1
}

Import-Module -Name $modulePath -Force

Invoke-Test 'Authentication window includes exact boundaries' {
    $start = [timespan]::Parse('03:58:00')
    $end = [timespan]::Parse('04:28:00')

    Assert-True (Test-InAuthenticationWindow -Now ([datetime]'2026-09-29 03:58:00') -Start $start -End $end)
    Assert-True (Test-InAuthenticationWindow -Now ([datetime]'2026-09-29 04:28:00') -Start $start -End $end)
}

Invoke-Test 'Authentication window excludes times immediately outside boundaries' {
    $start = [timespan]::Parse('03:58:00')
    $end = [timespan]::Parse('04:28:00')

    Assert-False (Test-InAuthenticationWindow -Now ([datetime]'2026-09-29 03:57:59') -Start $start -End $end)
    Assert-False (Test-InAuthenticationWindow -Now ([datetime]'2026-09-29 04:28:01') -Start $start -End $end)
}

Invoke-Test 'Raw JSON portal response is parsed' {
    $actual = ConvertFrom-PortalJsonp -Content '{"result":1,"message":"ok"}'
    Assert-Equal 1 $actual.result
    Assert-Equal 'ok' $actual.message
}

Invoke-Test 'JSONP portal response is parsed' {
    $actual = ConvertFrom-PortalJsonp -Content 'dr1234({"result":0,"v4ip":"10.0.0.8"});'
    Assert-Equal 0 $actual.result
    Assert-Equal '10.0.0.8' $actual.v4ip
}

Invoke-Test 'BOM and whitespace around JSONP are accepted' {
    $content = ([char]0xFEFF) + "  callback_1( {`"result`":1} ); `r`n"
    $actual = ConvertFrom-PortalJsonp -Content $content
    Assert-Equal 1 $actual.result
}

Invoke-Test 'Malformed portal response raises a controlled parsing error' {
    Assert-Throws -Body {
        ConvertFrom-PortalJsonp -Content 'not-json-or-jsonp'
    } -MessagePattern 'portal response'
}

Invoke-Test 'Portal query values with reserved and Unicode characters are encoded once' {
    $actual = ConvertTo-PortalQueryString -Parameters @{
        username = 'student 001'
        password = 'A&+%中文'
    }

    Assert-True ($actual -match 'username=student%20001')
    Assert-True ($actual -match 'password=A%26%2B%25%E4%B8%AD%E6%96%87')
    Assert-False ($actual -match '%2526') 'Reserved characters were encoded more than once.'
}

Invoke-Test 'DPAPI LocalMachine credential round trip does not store plaintext' {
    $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) ("campus-auth-{0}.bin" -f [guid]::NewGuid().ToString('N'))
    $username = 'student001'
    $plainPassword = 'P@ss&+%中文'
    $securePassword = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force

    try {
        Protect-CampusCredential -Username $username -Password $securePassword -Path $tempPath
        $stored = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($tempPath))
        Assert-False ($stored.Contains($username)) 'Encrypted file exposed the username.'
        Assert-False ($stored.Contains($plainPassword)) 'Encrypted file exposed the password.'

        $credential = Unprotect-CampusCredential -Path $tempPath
        Assert-Equal $username $credential.Username
        Assert-Equal $plainPassword $credential.Password
    }
    finally {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force
        }
    }
}

Invoke-Test 'Log redaction removes credentials query strings and cookies' {
    $username = 'student001'
    $password = 'P@ss&+%中文'
    $message = "Request for $username failed: https://p.cpu.edu.cn/drcom/login?DDDDD=$username&upass=$password Cookie: session=secret-cookie"
    $actual = Protect-LogMessage -Message $message -Secrets @($username, $password)

    Assert-False ($actual.Contains($username)) 'Redacted message exposed the username.'
    Assert-False ($actual.Contains($password)) 'Redacted message exposed the password.'
    Assert-False ($actual.Contains('secret-cookie')) 'Redacted message exposed a cookie.'
    Assert-False ($actual.Contains('?DDDDD=')) 'Redacted message exposed a query string.'
    Assert-True ($actual.Contains('https://p.cpu.edu.cn/drcom/login')) 'Redaction removed useful host and path context.'
}

Invoke-Test 'Log writer persists only redacted content' {
    $tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("campus-auth-logs-{0}" -f [guid]::NewGuid().ToString('N'))
    $username = 'student001'
    $password = 'P@ss&+%中文'

    try {
        Write-CampusLog -Level 'ERROR' -Event 'LoginFailed' -Message "user=$username password=$password https://p.cpu.edu.cn/drcom/login?upass=$password" -LogDirectory $tempDirectory -Secrets @($username, $password)
        $logFile = Get-ChildItem -LiteralPath $tempDirectory -Filter '*.log' | Select-Object -First 1
        Assert-True ($null -ne $logFile) 'No log file was created.'
        $content = Get-Content -LiteralPath $logFile.FullName -Raw -Encoding UTF8
        Assert-False ($content.Contains($username)) 'Log file exposed the username.'
        Assert-False ($content.Contains($password)) 'Log file exposed the password.'
        Assert-False ($content.Contains('?upass=')) 'Log file exposed a query string.'
        Assert-True ($content.Contains('[LoginFailed]')) 'Log event type is missing.'
    }
    finally {
        if (Test-Path -LiteralPath $tempDirectory) {
            Remove-Item -LiteralPath $tempDirectory -Recurse -Force
        }
    }
}

Invoke-Test 'Portal status maps an online JSONP response and current network identity' {
    $script:PortalRequestUris = New-Object System.Collections.ArrayList
    $invoker = {
        param($request)
        [void]$script:PortalRequestUris.Add([string]$request.Uri)
        return [pscustomobject]@{
            StatusCode = 200
            Content = 'probe({"result":1,"v4ip":"10.4.5.141","v6ip":"2001:db8::1","ss4":"AA-BB-CC-DD-EE-FF"})'
        }
    }

    $actual = Get-CampusPortalStatus -RequestInvoker $invoker
    Assert-True $actual.IsOnline
    Assert-Equal '10.4.5.141' $actual.IPv4
    Assert-Equal '2001:db8::1' $actual.IPv6
    Assert-Equal 'AABBCCDDEEFF' $actual.Mac
    Assert-Equal 1 $script:PortalRequestUris.Count
    Assert-True ($script:PortalRequestUris[0] -match '^https://p\.cpu\.edu\.cn/drcom/chkstatus\?')
}

Invoke-Test 'Portal context discovers ePortal configuration and fresh IP values' {
    $requestUris = New-Object System.Collections.ArrayList
    $rootHtml = @'
<html><head>
<script>v4ip='10.9.8.7';v6ip='2001:db8::7';page_data_encrypt='0';</script>
<script src="https://p.cpu.edu.cn:802/eportal/extern/PROGRAM01/PAGE02/pc.js"></script>
</head><body><input name="captcha" style="display:none" type="text"></body></html>
'@
    $invoker = {
        param($request)
        $uri = [string]$request.Uri
        [void]$requestUris.Add($uri)
        if ($uri -eq 'https://p.cpu.edu.cn/') {
            return [pscustomobject]@{ StatusCode = 200; Content = $rootHtml }
        }
        if ($uri -match '/drcom/chkstatus\?') {
            return [pscustomobject]@{ StatusCode = 200; Content = 's({"result":0,"v4ip":"10.9.8.9","v6ip":"2001:db8::9","ss4":"001122AABBCC"})' }
        }
        if ($uri -match ':802/eportal/portal/page/loadConfig\?') {
            return [pscustomobject]@{ StatusCode = 200; Content = 'c({"result":1,"data":{"login_method":"1"}})' }
        }
        throw "Unexpected test URI: $uri"
    }.GetNewClosure()

    $actual = Get-PortalContext -RequestInvoker $invoker
    Assert-Equal 'EPortal' $actual.Adapter
    Assert-Equal 1 $actual.LoginMethod
    Assert-Equal '10.9.8.9' $actual.IPv4
    Assert-Equal '2001:db8::9' $actual.IPv6
    Assert-Equal '001122AABBCC' $actual.Mac
    Assert-Equal 'PROGRAM01' $actual.ProgramIndex
    Assert-Equal 'PAGE02' $actual.PageIndex
    Assert-False $actual.CaptchaRequired
    Assert-False $actual.DataEncryptionRequired
    Assert-True (@($requestUris | Where-Object { $_ -match 'page/loadConfig' }).Count -eq 1)
}

Invoke-Test 'Portal context loads configuration when the landing page has no legacy extern script' {
    $requestUris = New-Object System.Collections.ArrayList
    $rootHtml = @'
<html><head><script src="a41.js?version=1787550484089"></script></head>
<body></body><script>page.run(1);</script></html>
'@
    $invoker = {
        param($request)
        $uri = [string]$request.Uri
        [void]$requestUris.Add($uri)
        if ($uri -eq 'https://p.cpu.edu.cn/') {
            return [pscustomobject]@{ StatusCode = 200; Content = $rootHtml }
        }
        if ($uri -match '/drcom/chkstatus\?') {
            return [pscustomobject]@{ StatusCode = 200; Content = 's({"result":0,"v4ip":"10.4.5.141","v6ip":"","ss4":"001122AABBCC","vlanid":1})' }
        }
        if ($uri -match ':802/eportal/portal/page/loadConfig\?' -and $uri -match '(?:\?|&)program_index=(?:&|$)') {
            return [pscustomobject]@{
                StatusCode = 200
                Content = 'c({"result":1,"data":{"program_index":"J3I42S1600394182","page_index":"DTT75f1600396179","page_style":"1","login_method":"1","redirect_url":""}})'
            }
        }
        throw "Unexpected test URI: $uri"
    }.GetNewClosure()

    $actual = Get-PortalContext -RequestInvoker $invoker

    Assert-Equal 'EPortal' $actual.Adapter
    Assert-Equal 1 $actual.LoginMethod
    Assert-Equal 'J3I42S1600394182' $actual.ProgramIndex
    Assert-Equal 'DTT75f1600396179' $actual.PageIndex
    Assert-Equal 1 @($requestUris | Where-Object { $_ -match 'page/loadConfig' }).Count
}

Invoke-Test 'DrCom login request uses required fields and single URL encoding' {
    $credential = [pscustomobject]@{ Username = 'student&1'; Password = 'A+%中文' }
    $context = [pscustomobject]@{
        Adapter = 'DrCom'; LoginMethod = 0; IPv4 = '10.1.2.3'; IPv6 = ''; Mac = '001122334455'
        CaptchaRequired = $false; DataEncryptionRequired = $false
    }

    $request = New-DrComLoginRequest -Credential $credential -Context $context
    Assert-Equal 'GET' $request.Method
    Assert-Equal 'DrCom' $request.Adapter
    Assert-True ($request.Uri -match '^https://p\.cpu\.edu\.cn/drcom/login\?')
    Assert-True ($request.Uri -match 'DDDDD=student%261')
    Assert-True ($request.Uri -match 'upass=A%2B%25%E4%B8%AD%E6%96%87')
    Assert-True ($request.Uri -match '0MKKey=123456')
    Assert-False ($request.Uri -match '%2526')
}

Invoke-Test 'ePortal login request uses account password method IP and MAC fields' {
    $credential = [pscustomobject]@{ Username = 'student001'; Password = 'secret' }
    $context = [pscustomobject]@{
        Adapter = 'EPortal'; LoginMethod = 1; IPv4 = '10.1.2.3'; IPv6 = '2001:db8::3'; Mac = '001122334455'
        Vlan = 1; AcIp = ''; AcName = ''; CaptchaRequired = $false; DataEncryptionRequired = $false
    }

    $request = New-EPortalLoginRequest -Credential $credential -Context $context
    Assert-Equal 'GET' $request.Method
    Assert-Equal 'EPortal' $request.Adapter
    Assert-True ($request.Uri -match '^https://p\.cpu\.edu\.cn:802/eportal/portal/login\?')
    Assert-True ($request.Uri -match 'user_account=student001')
    Assert-True ($request.Uri -match 'user_password=secret')
    Assert-True ($request.Uri -match 'login_method=1')
    Assert-True ($request.Uri -match 'wlan_user_ip=10\.1\.2\.3')
    Assert-True ($request.Uri -match 'wlan_user_mac=001122334455')
}

Invoke-Test 'Visible CAPTCHA prevents any automatic login request' {
    $script:LoginInvokerCalls = 0
    $credential = [pscustomobject]@{ Username = 'student001'; Password = 'secret' }
    $context = [pscustomobject]@{
        Adapter = 'DrCom'; LoginMethod = 0; IPv4 = '10.1.2.3'; IPv6 = ''; Mac = ''
        CaptchaRequired = $true; DataEncryptionRequired = $false
    }
    $invoker = {
        param($request)
        $script:LoginInvokerCalls++
        return [pscustomobject]@{ StatusCode = 200; Content = '{"result":1}' }
    }

    Assert-Throws -Body {
        Invoke-CampusPortalLogin -Credential $credential -Context $context -RequestInvoker $invoker
    } -MessagePattern 'CAPTCHA'
    Assert-Equal 0 $script:LoginInvokerCalls
}

Invoke-Test 'Successful portal login response is normalized' {
    $credential = [pscustomobject]@{ Username = 'student001'; Password = 'secret' }
    $context = [pscustomobject]@{
        Adapter = 'DrCom'; LoginMethod = 0; IPv4 = '10.1.2.3'; IPv6 = ''; Mac = ''
        CaptchaRequired = $false; DataEncryptionRequired = $false
    }
    $invoker = {
        param($request)
        return [pscustomobject]@{ StatusCode = 200; Content = 'loginCallback({"result":1,"msg":"login ok"})' }
    }

    $actual = Invoke-CampusPortalLogin -Credential $credential -Context $context -RequestInvoker $invoker
    Assert-True $actual.Success
    Assert-Equal 'DrCom' $actual.Adapter
    Assert-Equal 'login ok' $actual.Message
}

Invoke-Test 'Online window checks every interval without logging in or exiting early' {
    $state = [pscustomobject]@{
        Now = [datetime]'2026-09-29 03:58:00'
        StatusCalls = 0
        LoginCalls = 0
        Logs = New-Object System.Collections.ArrayList
    }
    $nowProvider = { $state.Now }.GetNewClosure()
    $sleepAction = { param($seconds) $state.Now = $state.Now.AddSeconds([double]$seconds) }.GetNewClosure()
    $statusAction = {
        $state.StatusCalls++
        return [pscustomobject]@{ IsOnline = $true }
    }.GetNewClosure()
    $loginAction = { $state.LoginCalls++ }.GetNewClosure()
    $logAction = { param($level, $event, $message) [void]$state.Logs.Add("$level|$event|$message") }.GetNewClosure()

    $actual = Invoke-AuthenticationWindow `
        -StartDate ([datetime]'2026-09-29') `
        -WindowStart ([timespan]::Parse('03:58:00')) `
        -WindowEnd ([timespan]::Parse('03:59:00')) `
        -IntervalSeconds 30 `
        -NowProvider $nowProvider `
        -SleepAction $sleepAction `
        -StatusAction $statusAction `
        -LoginAction $loginAction `
        -LogAction $logAction

    Assert-Equal 3 $state.StatusCalls
    Assert-Equal 0 $state.LoginCalls
    Assert-Equal 3 $actual.Checks
    Assert-Equal 'WindowComplete' $actual.ExitReason
}

Invoke-Test 'Offline round logs in once and the next round checks status again' {
    $state = [pscustomobject]@{
        Now = [datetime]'2026-09-29 03:58:00'
        StatusCalls = 0
        LoginCalls = 0
        Logs = New-Object System.Collections.ArrayList
    }
    $nowProvider = { $state.Now }.GetNewClosure()
    $sleepAction = { param($seconds) $state.Now = $state.Now.AddSeconds([double]$seconds) }.GetNewClosure()
    $statusAction = {
        $state.StatusCalls++
        return [pscustomobject]@{ IsOnline = ($state.StatusCalls -gt 1) }
    }.GetNewClosure()
    $loginAction = {
        $state.LoginCalls++
        return [pscustomobject]@{ Success = $true; Message = 'ok'; Adapter = 'DrCom' }
    }.GetNewClosure()
    $logAction = { param($level, $event, $message) [void]$state.Logs.Add("$level|$event|$message") }.GetNewClosure()

    $actual = Invoke-AuthenticationWindow `
        -StartDate ([datetime]'2026-09-29') `
        -WindowStart ([timespan]::Parse('03:58:00')) `
        -WindowEnd ([timespan]::Parse('03:58:30')) `
        -IntervalSeconds 30 `
        -NowProvider $nowProvider `
        -SleepAction $sleepAction `
        -StatusAction $statusAction `
        -LoginAction $loginAction `
        -LogAction $logAction

    Assert-Equal 2 $state.StatusCalls
    Assert-Equal 1 $state.LoginCalls
    Assert-Equal 1 $actual.LoginAttempts
}

Invoke-Test 'Delayed start inside the window runs through the exact final boundary' {
    $state = [pscustomobject]@{ Now = [datetime]'2026-09-29 04:27:30'; StatusCalls = 0 }
    $nowProvider = { $state.Now }.GetNewClosure()
    $sleepAction = { param($seconds) $state.Now = $state.Now.AddSeconds([double]$seconds) }.GetNewClosure()
    $statusAction = { $state.StatusCalls++; [pscustomobject]@{ IsOnline = $true } }.GetNewClosure()

    $actual = Invoke-AuthenticationWindow `
        -StartDate ([datetime]'2026-09-29') `
        -WindowStart ([timespan]::Parse('03:58:00')) `
        -WindowEnd ([timespan]::Parse('04:28:00')) `
        -IntervalSeconds 30 `
        -NowProvider $nowProvider `
        -SleepAction $sleepAction `
        -StatusAction $statusAction `
        -LoginAction { throw 'Login must not be called.' } `
        -LogAction { param($level, $event, $message) }

    Assert-Equal 2 $state.StatusCalls
    Assert-Equal 2 $actual.Checks
}

Invoke-Test 'Unaligned delayed start follows fixed slots and checks the exact final boundary' {
    $state = [pscustomobject]@{
        Now = [datetime]'2026-09-29 03:58:02'
        CheckTimes = New-Object System.Collections.ArrayList
    }
    $nowProvider = { $state.Now }.GetNewClosure()
    $sleepAction = { param($seconds) $state.Now = $state.Now.AddSeconds([double]$seconds) }.GetNewClosure()
    $statusAction = {
        [void]$state.CheckTimes.Add($state.Now.ToString('HH:mm:ss'))
        return [pscustomobject]@{ IsOnline = $true }
    }.GetNewClosure()

    $actual = Invoke-AuthenticationWindow `
        -StartDate ([datetime]'2026-09-29') `
        -WindowStart ([timespan]::Parse('03:58:00')) `
        -WindowEnd ([timespan]::Parse('04:00:00')) `
        -IntervalSeconds 30 `
        -NowProvider $nowProvider `
        -SleepAction $sleepAction `
        -StatusAction $statusAction `
        -LoginAction { throw 'Login must not be called.' } `
        -LogAction { param($level, $event, $message) }

    Assert-Equal '03:58:02,03:58:30,03:59:00,03:59:30,04:00:00' ($state.CheckTimes -join ',')
    Assert-Equal 5 $actual.Checks
}

Invoke-Test 'Final scheduled check runs when the clock wakes within the final second' {
    $state = [pscustomobject]@{
        Now = [datetime]'2026-10-08 04:27:30.500'
        CheckTimes = New-Object System.Collections.ArrayList
    }
    $nowProvider = { $state.Now }.GetNewClosure()
    $sleepAction = { param($seconds) $state.Now = $state.Now.AddSeconds([double]$seconds) }.GetNewClosure()
    $statusAction = {
        [void]$state.CheckTimes.Add($state.Now.ToString('HH:mm:ss.fff'))
        return [pscustomobject]@{ IsOnline = $true }
    }.GetNewClosure()

    $actual = Invoke-AuthenticationWindow `
        -StartDate ([datetime]'2026-10-08') `
        -WindowStart ([timespan]::Parse('03:58:00')) `
        -WindowEnd ([timespan]::Parse('04:28:00')) `
        -IntervalSeconds 30 `
        -NowProvider $nowProvider `
        -SleepAction $sleepAction `
        -StatusAction $statusAction `
        -LoginAction { throw 'Login must not be called.' } `
        -LogAction { param($level, $event, $message) }

    Assert-Equal '04:27:30.500,04:28:00.500' ($state.CheckTimes -join ',')
    Assert-Equal 2 $actual.Checks
}

Invoke-Test 'Time policy refusal backs off login attempts while status checks continue' {
    $state = [pscustomobject]@{
        Now = [datetime]'2026-09-29 03:58:00'
        StatusCalls = 0
        LoginTimes = New-Object System.Collections.ArrayList
        Logs = New-Object System.Collections.ArrayList
    }
    $nowProvider = { $state.Now }.GetNewClosure()
    $sleepAction = { param($seconds) $state.Now = $state.Now.AddSeconds([double]$seconds) }.GetNewClosure()
    $statusAction = {
        $state.StatusCalls++
        return [pscustomobject]@{ IsOnline = $false }
    }.GetNewClosure()
    $loginAction = {
        [void]$state.LoginTimes.Add($state.Now.ToString('HH:mm:ss'))
        return [pscustomobject]@{
            Success = $false
            Message = '时间策略设置本时段不允许上网'
            Adapter = 'EPortal'
        }
    }.GetNewClosure()
    $logAction = { param($level, $event, $message) [void]$state.Logs.Add("$level|$event|$message") }.GetNewClosure()

    $actual = Invoke-AuthenticationWindow `
        -StartDate ([datetime]'2026-09-29') `
        -WindowStart ([timespan]::Parse('03:58:00')) `
        -WindowEnd ([timespan]::Parse('04:00:30')) `
        -IntervalSeconds 30 `
        -PolicyBackoffSeconds 120 `
        -NowProvider $nowProvider `
        -SleepAction $sleepAction `
        -StatusAction $statusAction `
        -LoginAction $loginAction `
        -LogAction $logAction

    Assert-Equal 6 $state.StatusCalls
    Assert-Equal '03:58:00,04:00:00' ($state.LoginTimes -join ',')
    Assert-Equal 2 $actual.LoginAttempts
    Assert-True (@($state.Logs | Where-Object { $_ -match '\|PolicyBackoff\|' }).Count -ge 1)
}

Invoke-Test 'Start after 04:28 exits without contacting the portal' {
    $state = [pscustomobject]@{ Now = [datetime]'2026-09-29 04:28:01'; StatusCalls = 0 }
    $actual = Invoke-AuthenticationWindow `
        -StartDate ([datetime]'2026-09-29') `
        -WindowStart ([timespan]::Parse('03:58:00')) `
        -WindowEnd ([timespan]::Parse('04:28:00')) `
        -IntervalSeconds 30 `
        -NowProvider ({ $state.Now }.GetNewClosure()) `
        -SleepAction { param($seconds) throw 'Sleep must not be called.' } `
        -StatusAction { $state.StatusCalls++; throw 'Status must not be called.' } `
        -LoginAction { throw 'Login must not be called.' } `
        -LogAction { param($level, $event, $message) }

    Assert-Equal 0 $state.StatusCalls
    Assert-Equal 0 $actual.Checks
    Assert-Equal 'MissedWindow' $actual.ExitReason
}

Invoke-Test 'A status exception is logged and the next interval still runs' {
    $state = [pscustomobject]@{
        Now = [datetime]'2026-09-29 03:58:00'
        StatusCalls = 0
        LoginCalls = 0
        Logs = New-Object System.Collections.ArrayList
    }
    $nowProvider = { $state.Now }.GetNewClosure()
    $sleepAction = { param($seconds) $state.Now = $state.Now.AddSeconds([double]$seconds) }.GetNewClosure()
    $statusAction = {
        $state.StatusCalls++
        if ($state.StatusCalls -eq 1) { throw 'temporary portal timeout' }
        return [pscustomobject]@{ IsOnline = $true }
    }.GetNewClosure()
    $logAction = { param($level, $event, $message) [void]$state.Logs.Add("$level|$event|$message") }.GetNewClosure()

    $actual = Invoke-AuthenticationWindow `
        -StartDate ([datetime]'2026-09-29') `
        -WindowStart ([timespan]::Parse('03:58:00')) `
        -WindowEnd ([timespan]::Parse('03:58:30')) `
        -IntervalSeconds 30 `
        -NowProvider $nowProvider `
        -SleepAction $sleepAction `
        -StatusAction $statusAction `
        -LoginAction { throw 'Login must not be called.' } `
        -LogAction $logAction

    Assert-Equal 2 $state.StatusCalls
    Assert-Equal 2 $actual.Checks
    Assert-True (@($state.Logs | Where-Object { $_ -match 'ERROR\|CheckFailed\|temporary portal timeout' }).Count -eq 1)
}

Invoke-Test 'Scheduled task specification is SYSTEM daily at 03:58 and contains no credentials' {
    $installDirectory = 'C:\ProgramData\CPU-CampusNet-AutoAuth'
    $actual = Get-CampusScheduledTaskSpec -InstallDirectory $installDirectory

    Assert-Equal 'CPU-CampusNet-AutoAuth' $actual.TaskName
    Assert-Equal ([timespan]::Parse('03:58:00')) $actual.DailyAt
    Assert-Equal 'SYSTEM' $actual.UserId
    Assert-Equal 'ServiceAccount' $actual.LogonType
    Assert-Equal 'Highest' $actual.RunLevel
    Assert-Equal 'IgnoreNew' $actual.MultipleInstances
    Assert-True $actual.StartWhenAvailable
    Assert-Equal ([timespan]::Parse('03:58:00')) $actual.WindowStart
    Assert-Equal ([timespan]::Parse('04:28:00')) $actual.WindowEnd
    Assert-Equal 30 $actual.IntervalSeconds
    Assert-Equal 120 $actual.PolicyBackoffSeconds
    Assert-True ($actual.ExecutionTimeLimit -gt ($actual.WindowEnd - $actual.DailyAt)) 'Task time limit ends before the authentication window.'
    Assert-Equal ([timespan]::FromMinutes(40)) $actual.ExecutionTimeLimit
    Assert-True ($actual.Executable -match 'WindowsPowerShell\\v1\.0\\powershell\.exe$')
    Assert-True ($actual.Arguments -match '-File\s+"C:\\ProgramData\\CPU-CampusNet-AutoAuth\\CampusNetAuth\.ps1"')
    Assert-True ($actual.Arguments -match '-WindowStart\s+"03:58:00"')
    Assert-True ($actual.Arguments -match '-WindowEnd\s+"04:28:00"')
    Assert-True ($actual.Arguments -match '-IntervalSeconds\s+30')
    Assert-True ($actual.Arguments -match '-PolicyBackoffSeconds\s+120')
    Assert-False ($actual.Arguments -match '(?i)student|password|upass|DDDDD') 'Task command line contains credential-like data.'
}

Invoke-Test 'Install source validation requires every runtime file' {
    $tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("campus-auth-source-{0}" -f [guid]::NewGuid().ToString('N'))
    $required = @(
        'CampusNetAuth.Core.psm1',
        'CampusNetAuth.ps1',
        'Initialize-CampusNetCredential.ps1',
        'Uninstall-CampusNetAutoAuth.ps1'
    )

    try {
        New-Item -ItemType Directory -Path $tempDirectory -Force | Out-Null
        foreach ($name in $required) {
            New-Item -ItemType File -Path (Join-Path $tempDirectory $name) -Force | Out-Null
        }
        Assert-True (Test-CampusInstallSource -SourceDirectory $tempDirectory)

        Remove-Item -LiteralPath (Join-Path $tempDirectory 'CampusNetAuth.ps1') -Force
        Assert-False (Test-CampusInstallSource -SourceDirectory $tempDirectory)
    }
    finally {
        if (Test-Path -LiteralPath $tempDirectory) {
            Remove-Item -LiteralPath $tempDirectory -Recurse -Force
        }
    }
}

Invoke-Test 'Credential initializer helper runs the script and propagates failures' {
    $tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("campus-auth-initializer-{0}" -f [guid]::NewGuid().ToString('N'))
    $credentialPath = Join-Path $tempDirectory 'credential.bin'
    $markerPath = Join-Path $tempDirectory 'called.txt'
    $successScript = Join-Path $tempDirectory 'success.ps1'
    $failureScript = Join-Path $tempDirectory 'failure.ps1'

    try {
        New-Item -ItemType Directory -Path $tempDirectory -Force | Out-Null
        @'
param([string]$CredentialPath)
Set-Content -LiteralPath (Join-Path (Split-Path -Parent $CredentialPath) 'called.txt') -Value $CredentialPath -Encoding UTF8
'@ | Set-Content -LiteralPath $successScript -Encoding UTF8
        "throw 'simulated credential initialization failure'" |
            Set-Content -LiteralPath $failureScript -Encoding UTF8

        Invoke-CampusCredentialInitializer -ScriptPath $successScript -CredentialPath $credentialPath
        Assert-True (Test-Path -LiteralPath $markerPath -PathType Leaf)
        Assert-Equal $credentialPath ((Get-Content -LiteralPath $markerPath -Encoding UTF8 -Raw).Trim())

        Assert-Throws {
            Invoke-CampusCredentialInitializer -ScriptPath $failureScript -CredentialPath $credentialPath
        } 'simulated credential initialization failure'
    }
    finally {
        if (Test-Path -LiteralPath $tempDirectory) {
            Remove-Item -LiteralPath $tempDirectory -Recurse -Force
        }
    }
}

Invoke-Test 'Install ACL descriptor allows only SYSTEM and Administrators with inheritance disabled' {
    $acl = New-CampusInstallSecurityDescriptor
    Assert-True $acl.AreAccessRulesProtected

    $rules = @($acl.Access)
    Assert-Equal 2 $rules.Count
    $identities = @($rules | ForEach-Object {
        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    })
    Assert-True ($identities -contains 'S-1-5-18') 'SYSTEM SID rule is missing.'
    Assert-True ($identities -contains 'S-1-5-32-544') 'Administrators SID rule is missing.'
    foreach ($rule in $rules) {
        Assert-Equal 'Allow' ([string]$rule.AccessControlType)
        Assert-True (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne 0)
    }
}

Invoke-Test 'Entrypoint resolves default credential, log, and timing settings when launched with powershell.exe File' {
    $tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("campus-auth-entrypoint-{0}" -f [guid]::NewGuid().ToString('N'))
    $previousTestRoot = $env:CAMPUS_AUTH_TEST_ROOT

    try {
        New-Item -ItemType Directory -Path $tempDirectory -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $projectRoot 'CampusNetAuth.ps1') -Destination $tempDirectory -Force

        @'
function Unprotect-CampusCredential {
    param([string]$Path)
    $expected = Join-Path $env:CAMPUS_AUTH_TEST_ROOT 'credential.bin'
    if ([IO.Path]::GetFullPath($Path) -ne [IO.Path]::GetFullPath($expected)) {
        throw "Unexpected credential path: $Path"
    }
    return [pscustomobject]@{ Username = 'test-user'; Password = 'test-password' }
}

function Write-CampusLog {
    param($Level, $Event, $Message, [string]$LogDirectory, $Secrets)
    $expected = Join-Path $env:CAMPUS_AUTH_TEST_ROOT 'logs'
    if ([IO.Path]::GetFullPath($LogDirectory) -ne [IO.Path]::GetFullPath($expected)) {
        throw "Unexpected log directory: $LogDirectory"
    }
}

function Invoke-AuthenticationWindow {
    param($StartDate, $WindowStart, $WindowEnd, $IntervalSeconds, $PolicyBackoffSeconds, $NowProvider, $SleepAction, $StatusAction, $LoginAction, $LogAction)
    if ($WindowStart -ne [timespan]::Parse('03:58:00') -or $WindowEnd -ne [timespan]::Parse('04:28:00') -or
        $IntervalSeconds -ne 30 -or $PolicyBackoffSeconds -ne 120) {
        throw 'Unexpected default authentication timing.'
    }
    return [pscustomobject]@{ Checks = 0; LoginAttempts = 0; ExitReason = 'TestComplete' }
}

Export-ModuleMember -Function Unprotect-CampusCredential, Write-CampusLog, Invoke-AuthenticationWindow
'@ | Set-Content -LiteralPath (Join-Path $tempDirectory 'CampusNetAuth.Core.psm1') -Encoding UTF8

        $env:CAMPUS_AUTH_TEST_ROOT = $tempDirectory
        & powershell.exe `
            -NoLogo `
            -NoProfile `
            -ExecutionPolicy Bypass `
            -File (Join-Path $tempDirectory 'CampusNetAuth.ps1')
        $entrypointExitCode = $LASTEXITCODE

        Assert-Equal 0 $entrypointExitCode 'The entrypoint did not resolve paths relative to its own script directory.'
    }
    finally {
        $env:CAMPUS_AUTH_TEST_ROOT = $previousTestRoot
        if (Test-Path -LiteralPath $tempDirectory) {
            Remove-Item -LiteralPath $tempDirectory -Recurse -Force
        }
    }
}

Invoke-Test 'Deployment scripts exist and all PowerShell files parse without errors' {
    $requiredScripts = @(
        'Initialize-CampusNetCredential.ps1',
        'Install-CampusNetAutoAuth.ps1',
        'Uninstall-CampusNetAutoAuth.ps1'
    )
    foreach ($name in $requiredScripts) {
        Assert-True (Test-Path -LiteralPath (Join-Path $projectRoot $name) -PathType Leaf) "Missing deployment script: $name"
    }

    $powerShellFiles = @(Get-ChildItem -LiteralPath $projectRoot -Recurse -File | Where-Object {
        $_.Extension -in @('.ps1', '.psm1')
    })
    foreach ($file in $powerShellFiles) {
        $tokens = $null
        $errors = $null
        [void][Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
        Assert-Equal 0 @($errors).Count "PowerShell parser errors in $($file.FullName): $($errors -join '; ')"
    }
}

Invoke-Test 'Installer and uninstaller WhatIf modes make no system changes' {
    $installer = Join-Path $projectRoot 'Install-CampusNetAutoAuth.ps1'
    $uninstaller = Join-Path $projectRoot 'Uninstall-CampusNetAutoAuth.ps1'
    $installDirectory = Join-Path $env:ProgramData 'CPU-CampusNet-AutoAuth'
    $beforeDirectoryExists = Test-Path -LiteralPath $installDirectory
    $beforeTask = Get-ScheduledTask -TaskName 'CPU-CampusNet-AutoAuth' -ErrorAction SilentlyContinue

    & $installer -WhatIf
    & $uninstaller -WhatIf

    Assert-Equal $beforeDirectoryExists (Test-Path -LiteralPath $installDirectory) 'WhatIf changed the install directory state.'
    $afterTask = Get-ScheduledTask -TaskName 'CPU-CampusNet-AutoAuth' -ErrorAction SilentlyContinue
    Assert-Equal ([bool]$beforeTask) ([bool]$afterTask) 'WhatIf changed the scheduled task state.'
}

Write-Host ""
Write-Host "Passed: $script:Passed  Failed: $script:Failed"

if ($script:Failed -gt 0) {
    exit 1
}

exit 0
