<#
  kshrd.ps1 - local HTTPS reverse proxy for kshrd.app or any custom domain (demo use, this PC only).

  Run 'kshrd help' for the command list and examples.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command = 'help',
    [Parameter(Position = 1)][string]$Name,
    [Parameter(Position = 2)][int]$Port,
    [switch]$RemoveCA,
    [switch]$ClearHosts,
    [switch]$Force,
    [Alias('f')][switch]$Follow,
    [switch]$Errors,
    [Alias('h')][switch]$Help,
    [Alias('v')][switch]$Version
)

$ErrorActionPreference = 'Stop'

$AppVersion = '1.1.1'
$Domain     = 'kshrd.app'
# Traefik (Docker) owns the wildcard on 80/443. A dedicated loopback address keeps both proxies working.
$ListenIp   = '127.0.0.2'
$Root       = $PSScriptRoot
$SitesFile  = Join-Path $Root 'sites.json'
$CertDir    = Join-Path $Root 'certs'
$Prefix     = (Join-Path $Root 'nginx').Replace('\', '/') + '/'
$SitesDir   = Join-Path $Root 'nginx\conf\sites'
$PidFile    = Join-Path $Root 'nginx\logs\nginx.pid'
$HostsFile  = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$HostsBackup = Join-Path $Root 'hosts.backup'
$BlockBegin = "# BEGIN $Domain"
$BlockEnd   = "# END $Domain"
$RenewDays  = 30
$RunKey     = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$LogDir     = Join-Path $Root 'nginx\logs'

function Write-Color([string]$Text, [string]$Color, [switch]$NoNewline) {
    # https://no-color.org: any non-empty NO_COLOR turns colour off.
    $style = @{ NoNewline = [bool]$NoNewline }
    if ($Color -and -not $env:NO_COLOR) { $style.ForegroundColor = $Color }
    Write-Host $Text @style
}

function Write-Done([string]$Message) { Write-Color $Message 'Green' }

function Write-Heading([string]$Text) { Write-Color $Text 'Yellow' }

function Write-Row([string]$Left, [string]$Color, [string]$Right, [int]$Width) {
    Write-Color ("  {0,-$Width} " -f $Left) $Color -NoNewline
    Write-Host $Right
}

function Fail([string]$Message) {
    Write-Color 'error: ' 'Red' -NoNewline
    Write-Host $Message
    exit 1
}

function Write-LogLine([string]$Line) {
    $color = switch -Regex ($Line) {
        '" 5\d\d '                         { 'Red'; break }
        '\[(error|crit|alert|emerg)\]'      { 'Red'; break }
        '" 4\d\d '                         { 'Yellow'; break }
        '\[warn\]'                          { 'Yellow'; break }
    }
    Write-Color $Line $color
}

function Get-Tool([string]$Tool) {
    $found = Get-Command $Tool -ErrorAction SilentlyContinue
    if (-not $found) { Fail "$Tool is not installed or not on PATH." }
    $found.Source
}

function Get-Sites {
    $sites = [ordered]@{}
    if (Test-Path $SitesFile) {
        $json = Get-Content $SitesFile -Raw | ConvertFrom-Json
        foreach ($p in $json.PSObject.Properties) { $sites[$p.Name] = $p.Value }
    }
    $sites
}

function Save-Sites($Sites) {
    $sorted = [ordered]@{}
    foreach ($key in ($Sites.Keys | Sort-Object)) { $sorted[$key] = $Sites[$key] }
    [IO.File]::WriteAllText($SitesFile, (($sorted | ConvertTo-Json) + "`n"))
}

function Resolve-Hostname([string]$Value) {
    if (-not $Value) { Fail 'a site name is required.' }
    $value = $Value.ToLowerInvariant()
    if ($value -eq $Domain -or $value -eq '@') { return $Domain }
    if ($value.Contains('.')) {
        # A full domain name. The last label must start with a letter, which rules out IP addresses.
        $label = '[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
        if ($value.Length -gt 253 -or $value -notmatch "^($label\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$") {
            Fail "'$Value' is not a valid domain name, e.g. 'shop.test'. Wildcards are not supported."
        }
        # Browsers send *.localhost to 127.0.0.1 without reading the hosts file.
        if ($value.EndsWith('.localhost')) { Fail "'$Value' can't work here: browsers don't use the hosts file for .localhost names." }
        return $value
    }
    if ($value -notmatch '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$') {
        Fail "'$Value' is not a valid name. Use 'demo' for demo.$Domain, or a full domain such as 'shop.test'."
    }
    "$value.$Domain"
}

function Test-OwnCert([string]$Hostname) {
    # The shared certificate covers $Domain and one label below it. Anything else gets its own.
    $Hostname -notmatch "^([^.]+\.)?$([regex]::Escape($Domain))$"
}

function Get-CertExpiry([string]$Path) {
    # Returns nothing if the file is missing or unreadable.
    if (-not (Test-Path $Path)) { return }
    try {
        [Security.Cryptography.X509Certificates.X509Certificate2]::new($Path).NotAfter
    } catch {
        return
    }
}

function Test-CertNeedsRenewal([string]$BaseName) {
    $expiry = Get-CertExpiry (Join-Path $CertDir "$BaseName.pem")
    if (-not $expiry -or -not (Test-Path (Join-Path $CertDir "$BaseName-key.pem"))) { return $true }
    $expiry -lt (Get-Date).AddDays($RenewDays)
}

function Get-CertTargets($Sites) {
    $targets = @([pscustomobject]@{ BaseName = $Domain; Names = @($Domain, "*.$Domain") })
    foreach ($hostname in $Sites.Keys) {
        if (Test-OwnCert $hostname) { $targets += [pscustomobject]@{ BaseName = $hostname; Names = @($hostname) } }
    }
    $targets
}

function Invoke-Mkcert([string]$BaseName, [string[]]$Names) {
    # Issue to temporary files, so a failure leaves a working certificate in place.
    $newCert = Join-Path $CertDir "$BaseName.new.pem"
    $newKey = Join-Path $CertDir "$BaseName-key.new.pem"
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & (Get-Tool 'mkcert') -cert-file $newCert -key-file $newKey @Names 2>&1 | Out-String
        $ok = $LASTEXITCODE -eq 0
    } finally {
        $ErrorActionPreference = $previous
    }
    if (-not $ok) {
        Remove-Item $newCert, $newKey -Force -ErrorAction SilentlyContinue
        Write-Host $output.Trim()
        return $false
    }
    Move-Item $newCert (Join-Path $CertDir "$BaseName.pem") -Force
    Move-Item $newKey (Join-Path $CertDir "$BaseName-key.pem") -Force
    Write-Done ("Issued the certificate for {0}, valid until {1:yyyy-MM-dd}." -f $BaseName, (Get-CertExpiry (Join-Path $CertDir "$BaseName.pem")))
    $true
}

function New-Cert([string]$BaseName, [string[]]$Names) {
    if (-not (Test-CertNeedsRenewal $BaseName)) { return }
    if (-not (Invoke-Mkcert $BaseName $Names)) { Fail "mkcert could not issue the certificate for $BaseName." }
}

function Update-Certs([switch]$All) {
    # Returns how many were issued and how many failed.
    $result = [pscustomobject]@{ Issued = 0; Failed = 0 }
    foreach ($target in Get-CertTargets (Get-Sites)) {
        if (-not $All -and -not (Test-CertNeedsRenewal $target.BaseName)) { continue }
        if (Invoke-Mkcert $target.BaseName $target.Names) { $result.Issued++ } else { $result.Failed++ }
    }
    $result
}

function New-OwnCerts($Sites) {
    foreach ($hostname in $Sites.Keys) {
        if (Test-OwnCert $hostname) { New-Cert $hostname @($hostname) }
    }
}

function New-SiteConfig([string]$Hostname, $AppPort) {
    $tls = @"
    listen ${ListenIp}:443 ssl;
    http2 on;
    server_name $Hostname;
    access_log logs/$Hostname.access.log;
    error_log logs/$Hostname.error.log;
"@
    if (Test-OwnCert $Hostname) {
        $tls += @"

    ssl_certificate ../../certs/$Hostname.pem;
    ssl_certificate_key ../../certs/$Hostname-key.pem;
"@
    }
    if ($null -eq $AppPort) {
        return @"
server {
$tls

    location / {
        root html;
        index index.html;
    }
}
"@
    }
    # Apps may bind to either loopback family. Windows takes 2s to refuse a closed
    # loopback port, so fail over on a short connect timeout, and keep fail_timeout
    # short so a restarted app is reachable again almost immediately.
    @"
upstream $Hostname.upstream {
    server 127.0.0.1:$AppPort max_fails=1 fail_timeout=1s;
    server [::1]:$AppPort max_fails=0 backup;
}

server {
$tls

    set `$app_port $AppPort;

    location / {
        proxy_pass http://$Hostname.upstream;
        proxy_connect_timeout 250ms;
        proxy_http_version 1.1;
        proxy_set_header Host `$host;
        proxy_set_header X-Real-IP `$remote_addr;
        proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto `$scheme;
        proxy_set_header X-Forwarded-Host `$host;
        proxy_set_header Upgrade `$http_upgrade;
        proxy_set_header Connection `$connection_upgrade;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
    }

    error_page 502 504 /__kshrd_502.html;
    location = /__kshrd_502.html {
        internal;
        alias html/502.html;
        ssi on;
    }
}
"@
}

function Write-SiteConfigs($Sites) {
    New-Item -ItemType Directory -Force $SitesDir | Out-Null
    Get-ChildItem $SitesDir -Filter '*.conf' | Remove-Item -Force
    foreach ($hostname in $Sites.Keys) {
        $content = (New-SiteConfig $hostname $Sites[$hostname]) -replace "`r`n", "`n"
        [IO.File]::WriteAllText((Join-Path $SitesDir "$hostname.conf"), "$content`n")
    }
}

function Invoke-Nginx {
    $nginx = Get-Tool 'nginx'
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    Push-Location $Prefix
    try {
        $output = & $nginx -p $Prefix -c conf/nginx.conf @args 2>&1 | Out-String
        [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); Output = $output.Trim() }
    } finally {
        Pop-Location
        $ErrorActionPreference = $previous
    }
}

function Test-NginxConfig {
    $result = Invoke-Nginx -t
    if (-not $result.Ok) { Write-Host $result.Output }
    $result.Ok
}

function Test-NginxRunning {
    # 'nginx -t' can leave an empty pid file behind.
    $id = "$(Get-Content $PidFile -Raw -ErrorAction SilentlyContinue)".Trim()
    if (-not $id) { return $false }
    $process = Get-Process -Id $id -ErrorAction SilentlyContinue
    [bool]($process -and $process.ProcessName -eq 'nginx')
}

function Start-Nginx {
    if (Test-NginxRunning) { Write-Host 'nginx is already running.'; return }
    if (-not (Test-NginxConfig)) { Fail 'nginx config test failed.' }
    Start-Process (Get-Tool 'nginx') -ArgumentList '-p', $Prefix, '-c', 'conf/nginx.conf' `
        -WorkingDirectory $Prefix -WindowStyle Hidden
    foreach ($i in 1..20) {
        if (Test-NginxRunning) { Write-Done 'nginx started.'; return }
        Start-Sleep -Milliseconds 250
    }
    Get-Content (Join-Path $Root 'nginx\logs\error.log') -Tail 5 -ErrorAction SilentlyContinue | Write-Host
    Fail 'nginx did not start. Is another program using port 80 or 443?'
}

function Stop-Nginx {
    if (-not (Test-NginxRunning)) { Write-Host 'nginx is not running.'; return }
    $id = (Get-Content $PidFile -Raw).Trim()
    $result = Invoke-Nginx -s stop
    if (-not $result.Ok) { Fail $result.Output }
    Wait-Process -Id $id -Timeout 10 -ErrorAction SilentlyContinue
    Write-Done 'nginx stopped.'
}

function Update-Nginx {
    if (Test-NginxRunning) {
        $result = Invoke-Nginx -s reload
        if (-not $result.Ok) { Fail $result.Output }
        # The signal returns before the new worker has taken over.
        Start-Sleep -Milliseconds 500
        Write-Done 'nginx reloaded.'
    } else {
        Start-Nginx
    }
}

function Split-HostsBlock([string]$Text) {
    $Text -replace "(?s)$([regex]::Escape($BlockBegin)).*?$([regex]::Escape($BlockEnd))\r?\n?", ''
}

function Get-HostsContent([string[]]$Hostnames) {
    $text = [IO.File]::ReadAllText($HostsFile)
    $outside = Split-HostsBlock $text
    $eol = if ($outside -match "`r`n") { "`r`n" } else { "`n" }

    $missing = @()
    foreach ($hostname in $Hostnames) {
        $mapped = $outside -split "\r?\n" | Where-Object {
            $_ -notmatch '^\s*#' -and ($_ -split '\s+') -contains $hostname
        }
        if (-not $mapped) {
            $missing += $hostname
        } elseif (-not ($mapped | Where-Object { $_ -match "^\s*$([regex]::Escape($ListenIp))\s" })) {
            Write-Warning "$hostname is already mapped to another address in the hosts file, so it will not reach this proxy. Remove that line to use it here."
        }
    }
    if (-not $missing) { return $outside }

    $lines = @($BlockBegin) + ($missing | ForEach-Object { "$ListenIp $_" }) + @($BlockEnd)
    if ($outside -and -not $outside.EndsWith("`n")) { $outside += $eol }
    $outside + ($lines -join $eol) + $eol
}

function Write-HostsFile {
    # Runs elevated, re-invoked by Sync-Hosts.
    $hostnames = if ($ClearHosts) { @() } else { @((Get-Sites).Keys) }
    $content = Get-HostsContent $hostnames
    if (-not (Test-Path $HostsBackup)) { Copy-Item $HostsFile $HostsBackup }
    [IO.File]::WriteAllText($HostsFile, $content)
}

function Sync-Hosts([switch]$Clear) {
    $hostnames = if ($Clear) { @() } else { @((Get-Sites).Keys) }
    $current = [IO.File]::ReadAllText($HostsFile)
    $wanted = Get-HostsContent $hostnames
    if ($current -ceq $wanted) { return }

    Write-Host 'Updating the hosts file. Please approve the Windows admin prompt.'
    $shell = (Get-Process -Id $PID).Path
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '_write-hosts')
    if ($Clear) { $arguments += '-ClearHosts' }
    try {
        Start-Process $shell -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList $arguments
    } catch {
        Fail 'the admin prompt was declined, so the hosts file was not changed.'
    }
    if ([IO.File]::ReadAllText($HostsFile) -cne $wanted) {
        Fail 'the hosts file was not updated. Security software may be blocking the change.'
    }
    Write-Done 'Hosts file updated.'
}

function Test-Port([int]$AppPort) {
    foreach ($address in '127.0.0.1', '::1') {
        $client = [Net.Sockets.TcpClient]::new(([Net.IPAddress]::Parse($address)).AddressFamily)
        try {
            if ($client.ConnectAsync($address, $AppPort).Wait(300)) { return $true }
        } catch {
            # Refused; try the next address.
        } finally {
            $client.Dispose()
        }
    }
    $false
}

function Show-Status {
    Write-Host 'nginx: ' -NoNewline
    if (Test-NginxRunning) { Write-Color 'running' 'Green' } else { Write-Color 'stopped' 'Red' }
    $sites = Get-Sites
    if (-not $sites.Count) { Write-Host "No sites yet. Run 'kshrd setup'."; return }
    foreach ($hostname in $sites.Keys) {
        $appPort = $sites[$hostname]
        $target, $color = if ($null -eq $appPort) { 'placeholder page', 'DarkGray' }
                          elseif (Test-Port $appPort) { "localhost:$appPort (up)", 'Green' }
                          else { "localhost:$appPort (DOWN)", 'Red' }
        Write-Color ("  https://{0,-30} " -f $hostname) 'Cyan' -NoNewline
        Write-Color $target $color
    }
}

function Invoke-Renew {
    if (-not (Test-Path (Join-Path $CertDir "$Domain.pem"))) { Fail "run 'kshrd setup' first." }
    $result = Update-Certs -All:$Force
    if ($result.Issued -and (Test-NginxRunning)) { Update-Nginx }
    if ($result.Failed) { Fail "$($result.Failed) certificate(s) could not be issued." }
    if (-not $result.Issued) { Write-Host "All certificates are valid for more than $RenewDays days. Use -Force to reissue them anyway." }
}

function Invoke-Start {
    # After a reboot is the natural time to catch a certificate that is about to expire.
    # A failure here must not stop nginx: the current certificate may still be valid.
    if ((Test-Path (Join-Path $CertDir "$Domain.pem")) -and (Get-Command 'mkcert' -ErrorAction SilentlyContinue)) {
        $result = Update-Certs
        if ($result.Failed) { Write-Warning "$($result.Failed) certificate(s) could not be renewed." }
        if ($result.Issued -and (Test-NginxRunning)) { Update-Nginx }
    }
    # Pick up changes to the generated config after kshrd itself is updated.
    if (-not (Test-NginxRunning)) { Write-SiteConfigs (Get-Sites) }
    Start-Nginx
}

function Get-RegisteredHostname {
    $hostname = Resolve-Hostname $Name
    if (-not (Get-Sites).Contains($hostname)) { Fail "$hostname is not registered. Run 'kshrd list' to see the sites." }
    $hostname
}

function Invoke-Open {
    $hostname = Get-RegisteredHostname
    if (-not (Test-NginxRunning)) { Fail "nginx is not running. Run 'kshrd start' first." }
    Start-Process "https://$hostname"
    Write-Done "Opened https://$hostname"
}

function Invoke-Logs {
    $hostname = Get-RegisteredHostname
    $access = Join-Path $LogDir "$hostname.access.log"
    $errorLog = Join-Path $LogDir "$hostname.error.log"
    if ($Follow) {
        $path = if ($Errors) { $errorLog } else { $access }
        if (-not (Test-Path $path)) { Fail "no log for $hostname yet. If nginx has been running since before this update, run 'kshrd restart'." }
        Write-Color "Following $path. Press Ctrl+C to stop." 'DarkGray'
        Get-Content $path -Tail 20 -Wait | ForEach-Object { Write-LogLine $_ }
        return
    }
    $sections = [ordered]@{}
    if (-not $Errors) { $sections['Requests'] = $access }
    $sections['Errors'] = $errorLog
    foreach ($title in $sections.Keys) {
        Write-Heading "== $title =="
        $lines = if (Test-Path $sections[$title]) { Get-Content $sections[$title] -Tail 30 }
        if ($lines) { $lines | ForEach-Object { Write-LogLine $_ } } else { Write-Color '(empty)' 'DarkGray' }
    }
}

function Get-AutostartCommand {
    (Get-ItemProperty -Path $RunKey -Name 'kshrd' -ErrorAction SilentlyContinue).kshrd
}

function Invoke-Autostart {
    $action = if ($Name) { $Name.ToLowerInvariant() } else { 'status' }
    switch ($action) {
        'on' {
            $shell = (Get-Process -Id $PID).Path
            $value = "`"$shell`" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`" start"
            Set-ItemProperty -Path $RunKey -Name 'kshrd' -Value $value
            Write-Done 'nginx will start when you log in to Windows.'
        }
        'off' {
            Remove-ItemProperty -Path $RunKey -Name 'kshrd' -ErrorAction SilentlyContinue
            Write-Done 'nginx will no longer start when you log in.'
        }
        'status' {
            Write-Host ('Autostart is {0}.' -f $(if (Get-AutostartCommand) { 'on' } else { 'off' }))
        }
        default { Fail 'usage: kshrd autostart [on|off|status]' }
    }
}

function Get-HostsAddresses([string]$Hostname, [string]$Text) {
    # The addresses that active lines in the hosts file give this name.
    foreach ($line in $Text -split "\r?\n") {
        $fields = @(($line -replace '#.*$', '').Trim() -split '\s+')
        if ($fields.Count -ge 2 -and $fields[1..($fields.Count - 1)] -contains $Hostname) { $fields[0] }
    }
}

function Test-CertChain([string]$CertPath, [string]$CaPath) {
    # True if the certificate was issued by this CA.
    $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPath)
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.TrustMode = 'CustomRootTrust'
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        # Expiry is reported separately.
        $chain.ChainPolicy.VerificationFlags = 'IgnoreNotTimeValid'
        [void]$chain.ChainPolicy.CustomTrustStore.Add([Security.Cryptography.X509Certificates.X509Certificate2]::new($CaPath))
        $chain.Build($cert)
    } finally {
        $chain.Dispose()
    }
}

function Get-TlsError([string]$Hostname) {
    # Connects as a browser would, trusting what Windows trusts. Returns nothing on success.
    $client = [Net.Sockets.TcpClient]::new()
    try {
        if (-not $client.ConnectAsync($ListenIp, 443).Wait(1000)) { return 'connection timed out' }
        $stream = [Net.Security.SslStream]::new($client.GetStream())
        try {
            if (-not $stream.AuthenticateAsClientAsync($Hostname).Wait(3000)) { return 'handshake timed out' }
        } finally {
            $stream.Dispose()
        }
    } catch {
        $problem = $_.Exception
        while ($problem.InnerException) { $problem = $problem.InnerException }
        return $problem.Message
    } finally {
        $client.Dispose()
    }
}

function Write-Check([ValidateSet('ok', 'warn', 'fail')][string]$Level, [string]$Message, [string]$Fix) {
    $label, $color = switch ($Level) {
        'ok'   { 'ok  ', 'Green' }
        'warn' { 'warn', 'Yellow' }
        'fail' { 'FAIL', 'Red'; $script:DoctorFailures++ }
    }
    if ($Level -eq 'warn') { $script:DoctorWarnings++ }
    Write-Host '[' -NoNewline
    Write-Color $label $color -NoNewline
    Write-Host "] $Message"
    if ($Fix) {
        Write-Color '       fix: ' 'DarkGray' -NoNewline
        Write-Color $Fix 'Cyan'
    }
}

function Invoke-Doctor {
    $script:DoctorFailures = 0
    $script:DoctorWarnings = 0

    $toolsOk = $true
    foreach ($tool in 'nginx', 'mkcert') {
        $found = Get-Command $tool -ErrorAction SilentlyContinue
        if ($found) {
            Write-Check ok "$tool found"
        } else {
            $toolsOk = $false
            Write-Check fail "$tool is not installed or not on PATH" "install $tool, then open a new terminal"
        }
    }

    $sites = [ordered]@{}
    try {
        $sites = Get-Sites
        Write-Check ok "sites.json lists $($sites.Count) site(s)"
    } catch {
        Write-Check fail "sites.json can't be read: $($_.Exception.Message)" 'correct the file, or restore it with git'
    }

    # CA trust
    $caPath = $null
    if ($toolsOk) {
        $caPath = Join-Path "$(& mkcert -CAROOT)".Trim() 'rootCA.pem'
        if (-not (Test-Path $caPath)) {
            $caPath = $null
            Write-Check fail 'the local CA does not exist' 'kshrd setup'
        } else {
            $thumbprint = [Security.Cryptography.X509Certificates.X509Certificate2]::new($caPath).Thumbprint
            if ((Test-Path "Cert:\CurrentUser\Root\$thumbprint") -or (Test-Path "Cert:\LocalMachine\Root\$thumbprint")) {
                Write-Check ok 'the local CA is trusted by Windows'
            } else {
                Write-Check fail 'the local CA is not trusted by Windows' 'kshrd setup, then restart the browser'
            }
        }
    }

    # Certificates
    foreach ($target in Get-CertTargets $sites) {
        $path = Join-Path $CertDir "$($target.BaseName).pem"
        $expiry = Get-CertExpiry $path
        if (-not $expiry -or -not (Test-Path (Join-Path $CertDir "$($target.BaseName)-key.pem"))) {
            Write-Check fail "certificate for $($target.BaseName) is missing or unreadable" 'kshrd renew'
        } elseif ($expiry -lt (Get-Date)) {
            Write-Check fail "certificate for $($target.BaseName) expired on $($expiry.ToString('yyyy-MM-dd'))" 'kshrd renew'
        } elseif ($caPath -and -not (Test-CertChain $path $caPath)) {
            Write-Check fail "certificate for $($target.BaseName) was issued by a different CA" 'kshrd renew -Force'
        } elseif ($expiry -lt (Get-Date).AddDays($RenewDays)) {
            Write-Check warn "certificate for $($target.BaseName) expires on $($expiry.ToString('yyyy-MM-dd'))" 'kshrd renew'
        } else {
            Write-Check ok "certificate for $($target.BaseName) is valid until $($expiry.ToString('yyyy-MM-dd'))"
        }
    }

    # nginx
    $running = Test-NginxRunning
    if ($toolsOk) {
        if (Test-NginxConfig) {
            Write-Check ok 'nginx config is valid'
        } else {
            Write-Check fail 'nginx config is invalid (details above)' 'kshrd setup regenerates the site configs'
        }
    }
    if ($running) {
        Write-Check ok 'nginx is running'
    } else {
        Write-Check fail 'nginx is not running' 'kshrd start'
    }
    foreach ($listenPort in 80, 443) {
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $listenPort -ErrorAction SilentlyContinue |
            Where-Object LocalAddress -eq $ListenIp)
        $others = @($listeners | ForEach-Object { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } |
            Where-Object { $_ -ne 'nginx' } | Sort-Object -Unique)
        if ($others) {
            Write-Check fail "port $listenPort on $ListenIp is used by $($others -join ', ')" 'stop that program, then run kshrd restart'
        } elseif ($running -and -not $listeners) {
            Write-Check fail "nginx is not listening on ${ListenIp}:$listenPort" 'kshrd restart, and see nginx/logs/error.log'
        } else {
            Write-Check ok "port $listenPort on $ListenIp is available to nginx"
        }
    }

    # Each site
    $hostsText = [IO.File]::ReadAllText($HostsFile)
    foreach ($hostname in $sites.Keys) {
        $addresses = @(Get-HostsAddresses $hostname $hostsText)
        if (-not $addresses) {
            Write-Check fail "$hostname is not in the hosts file" 'kshrd setup'
        } elseif ($addresses[0] -ne $ListenIp) {
            Write-Check warn "$hostname goes to $($addresses[0]) instead of this proxy" 'delete that line from the hosts file, then run kshrd setup'
            continue
        }
        if ($running) {
            $tlsError = Get-TlsError $hostname
            if ($tlsError) {
                Write-Check fail "$hostname HTTPS check failed: $tlsError" 'kshrd renew -Force, then restart the browser'
                continue
            }
        }
        $appPort = $sites[$hostname]
        if ($null -ne $appPort -and -not (Test-Port $appPort)) {
            Write-Check warn "$hostname has no app on port $appPort" "start the app, or change the port with: kshrd add $hostname <port>"
        } elseif ($addresses) {
            Write-Check ok "$hostname is working$(if (-not $running) { ' (HTTPS not checked: nginx is stopped)' })"
        }
    }

    $autostart = Get-AutostartCommand
    if ($autostart -and -not $autostart.Contains("`"$PSCommandPath`"")) {
        Write-Check warn 'autostart points at a different copy of kshrd' 'kshrd autostart on'
    }

    Write-Host ''
    $color = if ($script:DoctorFailures) { 'Red' } elseif ($script:DoctorWarnings) { 'Yellow' } else { 'Green' }
    Write-Color "$($script:DoctorFailures) problem(s), $($script:DoctorWarnings) warning(s)." $color
    if ($script:DoctorFailures) { exit 1 }
}

function Invoke-Setup {
    $mkcert = Get-Tool 'mkcert'
    Get-Tool 'nginx' | Out-Null

    foreach ($dir in $CertDir, $SitesDir, (Join-Path $Root 'nginx\logs'), (Join-Path $Root 'nginx\temp')) {
        New-Item -ItemType Directory -Force $dir | Out-Null
    }

    Write-Host 'Trusting the local mkcert CA. Windows may ask you to confirm.'
    & $mkcert -install
    if ($LASTEXITCODE -ne 0) { Fail 'mkcert -install failed.' }

    New-Cert $Domain @($Domain, "*.$Domain")

    $sites = Get-Sites
    if (-not $sites.Contains($Domain)) { $sites[$Domain] = $null }
    New-OwnCerts $sites
    Save-Sites $sites
    Write-SiteConfigs $sites
    if (-not (Test-NginxConfig)) { Fail 'nginx config test failed.' }
    Sync-Hosts
    Update-Nginx
    Show-Status
}

function Set-Sites($Sites) {
    # Apply the change, rolling back if nginx rejects the result.
    $previous = Get-Sites
    Write-SiteConfigs $Sites
    if (-not (Test-NginxConfig)) {
        Write-SiteConfigs $previous
        Fail 'nginx rejected the new config; nothing was changed.'
    }
    Save-Sites $Sites
    Sync-Hosts
    Update-Nginx
}

function Invoke-Add {
    if ($Port -lt 1 -or $Port -gt 65535) { Fail 'usage: kshrd add <name> <port>' }
    if ($Port -in 80, 443) { Fail "port $Port is used by nginx itself." }
    if (-not (Test-Path (Join-Path $CertDir "$Domain.pem"))) { Fail "run 'kshrd setup' first." }
    $hostname = Resolve-Hostname $Name
    $sites = Get-Sites
    $sites[$hostname] = $Port
    New-OwnCerts $sites
    Set-Sites $sites
    Write-Color "https://$hostname" 'Cyan' -NoNewline
    Write-Host " -> localhost:$Port"
    if (Test-OwnCert $hostname) {
        Write-Host "Note: if $hostname is a real site on the internet, this PC can't reach it until you remove this entry."
    }
    if (-not (Test-Port $Port)) { Write-Warning "nothing is listening on port $Port yet." }
}

function Invoke-Remove {
    $hostname = Resolve-Hostname $Name
    $sites = Get-Sites
    if (-not $sites.Contains($hostname)) { Fail "$hostname is not registered." }
    if ($hostname -eq $Domain) {
        # The bare domain stays registered and falls back to the placeholder page.
        $sites[$Domain] = $null
    } else {
        $sites.Remove($hostname)
    }
    Set-Sites $sites
    if (Test-OwnCert $hostname) {
        Remove-Item (Join-Path $CertDir "$hostname.pem"), (Join-Path $CertDir "$hostname-key.pem") -Force -ErrorAction SilentlyContinue
    }
    if ($hostname -ne $Domain) {
        # A worker that is still finishing may hold these open, so this is best effort.
        Remove-Item (Join-Path $LogDir "$hostname.access.log"), (Join-Path $LogDir "$hostname.error.log") -Force -ErrorAction SilentlyContinue
    }
    Write-Done "Removed $hostname."
}

function Invoke-Teardown {
    Stop-Nginx
    Sync-Hosts -Clear
    if ($RemoveCA) {
        & (Get-Tool 'mkcert') -uninstall
        if ($LASTEXITCODE -ne 0) { Fail 'mkcert -uninstall failed.' }
    }
    Write-Done "Torn down. sites.json is kept, so 'kshrd setup' restores everything."
}

$HelpTopics = [ordered]@{
    setup    = @{
        Usage    = 'kshrd setup'
        Summary  = 'First run: trust the CA, issue the certificate, update hosts, start nginx'
        Details  = 'Safe to run again. Windows may ask you to confirm the CA and the hosts file change.'
        Examples = @(, @('kshrd setup', 'Prepare this PC'))
    }
    add      = @{
        Usage    = 'kshrd add <name> <port>'
        Summary  = 'Point a subdomain or custom domain at an app on localhost, or change its port'
        Details  = "<name> is a subdomain, $Domain for the main site, or a full custom domain, which gets its own certificate. Prefer the reserved .test ending for made-up names, because a real site with the same name can't be reached from this PC while the entry exists. <port> is 1-65535, except 80 and 443."
        Examples = @(
            @('kshrd add shop.test 3000', 'https://shop.test -> localhost:3000'),
            @('kshrd add demo 3000', "https://demo.$Domain -> localhost:3000"),
            @("kshrd add $Domain 3000", "https://$Domain -> localhost:3000")
        )
    }
    remove   = @{
        Usage    = 'kshrd remove <name>'
        Summary  = 'Remove a site'
        Details  = "A custom domain's certificate is deleted too. Removing $Domain keeps it registered and brings back the placeholder page."
        Examples = @(
            @('kshrd remove shop.test', 'Stop serving https://shop.test'),
            @('kshrd remove demo', "Stop serving https://demo.$Domain")
        )
    }
    open     = @{
        Usage    = 'kshrd open <name>'
        Summary  = 'Open a site in your default browser'
        Details  = '<name> is written the same way as for kshrd add.'
        Examples = @(
            @('kshrd open shop.test', 'Open https://shop.test'),
            @('kshrd open demo', "Open https://demo.$Domain")
        )
    }
    logs     = @{
        Usage    = 'kshrd logs <name> [-Follow] [-Errors]'
        Summary  = 'Show the recent requests and errors for one site'
        Details  = 'Shows the last 30 lines of each log. -Follow (or -f) keeps watching the requests until you press Ctrl+C. -Errors shows only the errors, and can be combined with -Follow.'
        Examples = @(
            @('kshrd logs shop.test', 'Show recent requests and errors'),
            @('kshrd logs shop.test -f', 'Watch requests as they arrive'),
            @('kshrd logs shop.test -Errors', 'Show only the errors')
        )
    }
    list     = @{
        Usage    = 'kshrd list'
        Summary  = 'Show nginx, each site, and whether its app is up'
        Details  = 'Same as kshrd status.'
        Examples = @(, @('kshrd list', 'Show all sites'))
    }
    status   = @{
        Usage    = 'kshrd status'
        Summary  = 'Same as kshrd list'
        Details  = 'Same as kshrd list.'
        Examples = @(, @('kshrd status', 'Show all sites'))
    }
    start    = @{
        Usage    = 'kshrd start'
        Summary  = 'Start nginx'
        Details  = 'Also renews certificates that expire soon. Run this after a reboot, or use kshrd autostart on.'
        Examples = @(, @('kshrd start', 'Start serving sites'))
    }
    stop     = @{
        Usage    = 'kshrd stop'
        Summary  = 'Stop nginx'
        Details  = 'Sites and hosts entries are kept.'
        Examples = @(, @('kshrd stop', 'Stop serving sites'))
    }
    restart  = @{
        Usage    = 'kshrd restart'
        Summary  = 'Stop nginx, then start it again'
        Details  = 'Sites and hosts entries are kept.'
        Examples = @(, @('kshrd restart', 'Restart nginx'))
    }
    teardown = @{
        Usage    = 'kshrd teardown [-RemoveCA]'
        Summary  = 'Stop nginx and remove the hosts entries'
        Details  = "-RemoveCA also removes the local CA from the trust store. sites.json is kept, so 'kshrd setup' restores everything."
        Examples = @(
            @('kshrd teardown', 'Stop nginx and remove the hosts entries'),
            @('kshrd teardown -RemoveCA', 'Also remove the local CA')
        )
    }
    autostart = @{
        Usage    = 'kshrd autostart [on|off|status]'
        Summary  = 'Start nginx when you log in to Windows'
        Details  = 'Applies to your Windows user only and needs no admin rights. If you move this folder, run kshrd autostart on again.'
        Examples = @(
            @('kshrd autostart on', 'Start nginx at every login'),
            @('kshrd autostart off', 'Go back to starting it by hand')
        )
    }
    doctor   = @{
        Usage    = 'kshrd doctor'
        Summary  = 'Check for problems and suggest a fix for each'
        Details  = 'Checks the tools, CA trust, certificates, nginx, ports, hosts entries and a real HTTPS connection to each site. Changes nothing. Exits with 1 if it finds a problem; warnings do not count.'
        Examples = @(, @('kshrd doctor', 'Check everything'))
    }
    renew    = @{
        Usage    = 'kshrd renew [-Force]'
        Summary  = 'Reissue certificates that expire soon'
        Details  = "Reissues any certificate that is missing or has less than $RenewDays days left, then reloads nginx. kshrd start and kshrd setup do this too. -Force reissues every certificate."
        Examples = @(
            @('kshrd renew', 'Reissue certificates that need it'),
            @('kshrd renew -Force', 'Reissue all certificates')
        )
    }
    version  = @{
        Usage    = 'kshrd version'
        Summary  = 'Show the kshrd version'
        Details  = 'kshrd --version and -v do the same.'
        Examples = @(, @('kshrd version', 'Show the version'))
    }
    help     = @{
        Usage    = 'kshrd help [command]'
        Summary  = 'Show this list, or the details of one command'
        Details  = 'kshrd <command> --help and -h do the same.'
        Examples = @(
            @('kshrd help', 'List all commands'),
            @('kshrd help add', 'Show details for add')
        )
    }
}

function Write-Examples($Examples) {
    Write-Heading 'Examples:'
    foreach ($example in $Examples) { Write-Row $example[0] 'Green' $example[1] 30 }
}

function Show-Help([string]$Topic) {
    if ($Topic) {
        $key = $Topic.ToLowerInvariant()
        if (-not $HelpTopics.Contains($key)) { Fail "unknown command '$Topic'. Run 'kshrd help' for the list." }
        $entry = $HelpTopics[$key]
        Write-Heading 'Usage:'
        Write-Color "  $($entry.Usage)" 'Cyan'
        Write-Host ''
        Write-Host $entry.Summary
        Write-Host $entry.Details
        Write-Host ''
        Write-Examples $entry.Examples
        return
    }
    Write-Color 'kshrd' 'Cyan' -NoNewline
    Write-Host " $AppVersion - local HTTPS reverse proxy for $Domain or any custom domain (this PC only)"
    Write-Host ''
    Write-Heading 'Usage:'
    Write-Host '  kshrd <command> [arguments]'
    Write-Host ''
    Write-Heading 'Commands:'
    foreach ($key in $HelpTopics.Keys) {
        Write-Row $HelpTopics[$key].Usage.Substring(6) 'Cyan' $HelpTopics[$key].Summary 36
    }
    Write-Host ''
    Write-Heading 'Names:'
    Write-Row 'demo' 'Cyan' "A subdomain: https://demo.$Domain" 36
    Write-Row $Domain 'Cyan' 'The main site' 36
    Write-Row 'shop.test' 'Cyan' 'A custom domain, used exactly as written, with its own certificate' 36
    Write-Host ''
    Write-Examples @(
        @('kshrd setup', 'First run on this PC'),
        @('kshrd add shop.test 3000', 'https://shop.test -> localhost:3000'),
        @('kshrd add demo 3000', "https://demo.$Domain -> localhost:3000"),
        @("kshrd add $Domain 3000", "https://$Domain -> localhost:3000"),
        @('kshrd open shop.test', 'Open it in the browser'),
        @('kshrd logs shop.test -f', 'Watch its requests'),
        @('kshrd list', 'Check nginx and each site'),
        @('kshrd doctor', 'Find out why something is not working'),
        @('kshrd remove shop.test', 'Remove a site'),
        @('kshrd autostart on', 'Start nginx at every login')
    )
    Write-Host ''
    Write-Host "Run 'kshrd help <command>' for details."
}

# Dot-sourced by the tests, which only want the functions above.
if ($MyInvocation.InvocationName -eq '.') { return }

if ($Version -or $Command -eq '--version') {
    Write-Host "kshrd $AppVersion"
    exit 0
}

$HelpFlags = '--help', '-help', '-h', '/?'
if ($Help -or $Command -in $HelpFlags -or $Name -in $HelpFlags) {
    # 'help' is also the default command, so a bare 'kshrd -h' must show the full list.
    $topic = if ($Command -in ($HelpFlags + 'help')) { $Name } else { $Command }
    Show-Help $(if ($topic -notin $HelpFlags) { $topic })
    exit 0
}

switch ($Command.ToLowerInvariant()) {
    'setup'        { Invoke-Setup }
    'add'          { Invoke-Add }
    'remove'       { Invoke-Remove }
    'list'         { Show-Status }
    'status'       { Show-Status }
    'start'        { Invoke-Start }
    'stop'         { Stop-Nginx }
    'restart'      { Stop-Nginx; Invoke-Start }
    'renew'        { Invoke-Renew }
    'doctor'       { Invoke-Doctor }
    'open'         { Invoke-Open }
    'logs'         { Invoke-Logs }
    'autostart'    { Invoke-Autostart }
    'teardown'     { Invoke-Teardown }
    'version'      { Write-Host "kshrd $AppVersion" }
    'help'         { Show-Help $Name }
    '_write-hosts' { Write-HostsFile }
    default        { Fail "unknown command '$Command'. Run 'kshrd help' for the list." }
}
