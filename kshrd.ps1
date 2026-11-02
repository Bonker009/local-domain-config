<#
  kshrd.ps1 - local HTTPS reverse proxy for kshrd.app or any custom domain (demo use, this PC only).

  Run 'kshrd help' for the command list and examples.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command = 'help',
    [Parameter(Position = 1)][string]$Name,
    [Parameter(Position = 2)][string]$Target,
    [Parameter(Position = 3, ValueFromRemainingArguments)][string[]]$Rest,
    [switch]$RemoveCA,
    [switch]$ClearHosts,
    [switch]$Force,
    [Alias('f')][switch]$Follow,
    [Alias('y')][switch]$Yes,
    [switch]$Json,
    [switch]$Clear,
    [switch]$Errors,
    [Alias('h')][switch]$Help,
    [Alias('v')][switch]$Version
)

$ErrorActionPreference = 'Stop'

# Unset, this would count as one empty argument.
$Rest = @($Rest | Where-Object { $_ })

$AppVersion = '1.2.1'
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
$ProjectFile = 'kshrd.json'
$LogWarnBytes = 100MB
# Endings that are not public, so a name using one can't hide a real website.
$PrivateEndings = 'test', 'example', 'invalid', 'local', 'localdomain', 'internal', 'intranet', 'lan', 'home', 'corp'

function Write-Color([string]$Text, [string]$Color, [switch]$NoNewline) {
    # https://no-color.org: any non-empty NO_COLOR turns colour off.
    $style = @{ NoNewline = [bool]$NoNewline }
    if ($Color -and -not $env:NO_COLOR) { $style.ForegroundColor = $Color }
    Write-Host $Text @style
}

function Write-Done([string]$Message) { Write-Color $Message 'Green' }

function Write-Heading([string]$Text) { Write-Color $Text 'Yellow' }

function New-Cell([string]$Text, [string]$Color) {
    [pscustomobject]@{ Text = $Text; Color = $Color }
}

function Get-ConsoleWidth {
    # Piped output is not wrapped, so it stays easy to search.
    if ([Console]::IsOutputRedirected) { return 10000 }
    try { [Math]::Max([Console]::WindowWidth, 40) } catch { 120 }
}

function Split-TextToWidth([string]$Text, [int]$Width) {
    # Wraps on spaces, and breaks a word only if it is longer than the line.
    $line = ''
    foreach ($word in $Text -split ' ') {
        while ($word.Length -gt $Width) {
            if ($line) { $line; $line = '' }
            $word.Substring(0, $Width)
            $word = $word.Substring($Width)
        }
        if (-not $line) { $line = $word }
        elseif ($line.Length + 1 + $word.Length -le $Width) { $line += " $word" }
        else { $line; $line = $word }
    }
    $line
}

function Get-ColumnWidths([int[]]$Natural, [int]$MaxWidth) {
    # Takes from the widest column until the table fits, including '| ' and ' |' borders.
    $widths = @($Natural)
    $available = $MaxWidth - (3 * $widths.Count + 1)
    while (($widths | Measure-Object -Sum).Sum -gt $available) {
        $widest = [array]::IndexOf($widths, [int]($widths | Measure-Object -Maximum).Maximum)
        if ($widths[$widest] -le 8) { break }
        $widths[$widest]--
    }
    $widths
}

function Write-Table([string[]]$Headers, $Rows, [int]$MaxWidth = (Get-ConsoleWidth)) {
    # Each row is an array of cells from New-Cell.
    # PowerShell unwraps a one-row result, leaving a bare list of cells.
    if ($Rows -isnot [array] -or $Rows[0] -isnot [array]) { $Rows = , @($Rows) }
    $natural = for ($i = 0; $i -lt $Headers.Count; $i++) {
        $longest = $Headers[$i].Length
        foreach ($row in $Rows) { $longest = [Math]::Max($longest, $row[$i].Text.Length) }
        $longest
    }
    $widths = @(Get-ColumnWidths $natural $MaxWidth)
    $border = '+' + (($widths | ForEach-Object { '-' * ($_ + 2) }) -join '+') + '+'

    $writeRow = {
        param($Cells)
        $wrapped = [Collections.Generic.List[object]]::new()
        $height = 0
        for ($i = 0; $i -lt $Cells.Count; $i++) {
            $lines = @(Split-TextToWidth $Cells[$i].Text $widths[$i])
            $wrapped.Add($lines)
            $height = [Math]::Max($height, $lines.Count)
        }
        for ($lineIndex = 0; $lineIndex -lt $height; $lineIndex++) {
            for ($i = 0; $i -lt $Cells.Count; $i++) {
                Write-Color '| ' 'DarkGray' -NoNewline
                $text = if ($lineIndex -lt $wrapped[$i].Count) { $wrapped[$i][$lineIndex] } else { '' }
                Write-Color $text.PadRight($widths[$i]) $Cells[$i].Color -NoNewline
                Write-Color ' ' '' -NoNewline
            }
            Write-Color '|' 'DarkGray'
        }
    }

    Write-Color $border 'DarkGray'
    & $writeRow @($Headers | ForEach-Object { New-Cell $_ 'Yellow' })
    Write-Color $border 'DarkGray'
    foreach ($row in $Rows) { & $writeRow $row }
    Write-Color $border 'DarkGray'
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

function ConvertTo-RoutePath([string]$Path) {
    if ($Path -notmatch '^/[A-Za-z0-9._~/-]*$' -or $Path -match '(^|/)\.\.(/|$)') {
        Fail "'$Path' is not a valid path. Use something like /api."
    }
    $trimmed = $Path.TrimEnd('/')
    if ($trimmed) { $trimmed } else { '/' }
}

function ConvertTo-StoredTarget([string]$Text, [string]$BaseDir) {
    # Turns what the user typed into what sites.json stores:
    # a number for a local port, 'host:port' for another machine, 'dir:<path>' for a folder.
    $text = $Text.Trim()
    if (-not $text) { Fail 'a port, host:port or folder is required.' }
    if ($text -match '^\d+$' -or $text -match '^localhost:(\d+)$') {
        $number = [long]$(if ($Matches[1]) { $Matches[1] } else { $text })
        if ($number -lt 1 -or $number -gt 65535) { Fail "port $number is not between 1 and 65535." }
        if ($number -in 80, 443) { Fail "port $number is used by nginx itself." }
        return [int]$number
    }
    if ($text -match '^([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):(\d+)$') {
        if ([long]$Matches[2] -lt 1 -or [long]$Matches[2] -gt 65535) { Fail "'$text' has a port that is not between 1 and 65535." }
        return $text
    }
    $full = [IO.Path]::GetFullPath($text, $BaseDir)
    if (-not (Test-Path $full -PathType Container)) { Fail "'$text' is not a port, a host:port or an existing folder." }
    # These would be read as nginx syntax.
    if ($full -match '["$;{}]') { Fail "the folder '$full' contains a character nginx can't use." }
    'dir:' + $full.Replace('\', '/').TrimEnd('/')
}

function Get-TargetKind($Stored) {
    if ("$Stored" -match '^\d+$') { 'port' } elseif ("$Stored".StartsWith('dir:')) { 'dir' } else { 'remote' }
}

function Get-TargetText($Stored) {
    switch (Get-TargetKind $Stored) {
        'port' { "localhost:$Stored" }
        'dir' { "$Stored".Substring(4) }
        default { "$Stored" }
    }
}

function Get-Routes($Value) {
    # Every site value as path -> stored target: nothing, a single target, or several routes.
    $routes = [ordered]@{}
    if ($null -eq $Value) { return , $routes }
    if ($Value -is [Collections.IDictionary]) {
        foreach ($key in $Value.Keys) { $routes[[string]$key] = $Value[$key] }
    } elseif ($Value -is [pscustomobject]) {
        foreach ($p in $Value.PSObject.Properties) { $routes[$p.Name] = $p.Value }
    } else {
        $routes['/'] = $Value
    }
    , $routes
}

function Compress-Routes($Routes) {
    # Keeps sites.json simple: a site with only a root route stays a plain value.
    if ($Routes.Count -eq 0) { return $null }
    if ($Routes.Count -eq 1 -and $Routes.Contains('/')) { return $Routes['/'] }
    , $Routes
}

function Test-Remote([string]$Address) {
    $at = $Address.LastIndexOf(':')
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.ConnectAsync($Address.Substring(0, $at).Trim('[', ']'), [int]$Address.Substring($at + 1)).Wait(1000)
    } catch {
        $false
    } finally {
        $client.Dispose()
    }
}

function Test-Target($Stored) {
    switch (Get-TargetKind $Stored) {
        'port' { Test-Port ([int]$Stored) }
        'dir' { Test-Path "$Stored".Substring(4) -PathType Container }
        default { Test-Remote "$Stored" }
    }
}

function Test-RealDomain([string]$Hostname) {
    # Asks DNS, not the hosts file. An offline PC just gets no warning.
    if (-not (Test-OwnCert $Hostname)) { return $false }
    if ($Hostname.Substring($Hostname.LastIndexOf('.') + 1) -in $PrivateEndings) { return $false }
    try {
        [bool](Resolve-DnsName $Hostname -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -in 'A', 'AAAA' })
    } catch {
        $false
    }
}

function Confirm-Action([string]$Message) {
    # With no one to ask, as in a script, warn and carry on.
    if ($Yes -or [Console]::IsInputRedirected) {
        Write-Warning $Message
        return $true
    }
    Write-Color $Message 'Yellow'
    (Read-Host 'Continue? [Y/n]') -notmatch '^\s*n'
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

function New-ProxyLocation([string]$Match, [string]$Upstream, [string]$Label, [string]$ConnectTimeout) {
    @"
    location $Match {
        set `$app_port "$Label";
        proxy_pass http://$Upstream;
        proxy_connect_timeout $ConnectTimeout;
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
"@
}

function New-SiteConfig([string]$Hostname, $Value) {
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
    $routes = Get-Routes $Value
    if ($routes.Count -eq 0) {
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

    $upstreams = @()
    $locations = @()
    $proxied = $false
    $index = 0
    foreach ($path in $routes.Keys) {
        $stored = $routes[$path]
        $kind = Get-TargetKind $stored
        if ($kind -eq 'dir') {
            $folder = "$stored".Substring(4)
            if ($path -eq '/') {
                $locations += "    location / {`n        root `"$folder`";`n        index index.html;`n    }"
            } else {
                $locations += "    location = $path {`n        return 301 $path/;`n    }"
                $locations += "    location $path/ {`n        alias `"$folder/`";`n        index index.html;`n    }"
            }
            continue
        }
        $proxied = $true
        $upstream = if ($index) { "$Hostname.upstream$index" } else { "$Hostname.upstream" }
        $index++
        if ($kind -eq 'port') {
            # Apps may bind to either loopback family. Windows takes 2s to refuse a closed
            # loopback port, so fail over on a short connect timeout, and keep fail_timeout
            # short so a restarted app is reachable again almost immediately.
            $upstreams += "upstream $upstream {`n    server 127.0.0.1:$stored max_fails=1 fail_timeout=1s;`n    server [::1]:$stored max_fails=0 backup;`n}"
            $label = "$stored"
            $timeout = '250ms'
        } else {
            $upstreams += "upstream $upstream {`n    server $stored max_fails=1 fail_timeout=1s;`n}"
            $label = "$stored"
            $timeout = '3s'
        }
        if ($path -eq '/') {
            $locations += New-ProxyLocation '/' $upstream $label $timeout
        } else {
            # Both forms, because a redirect from /api to /api/ would lose a POST body.
            $locations += New-ProxyLocation "= $path" $upstream $label $timeout
            $locations += New-ProxyLocation "$path/" $upstream $label $timeout
        }
    }
    # Without this, nginx would answer other paths from its own html folder.
    if (-not $routes.Contains('/')) { $locations += "    location / {`n        return 404;`n    }" }
    if ($proxied) {
        $locations += @"
    error_page 502 504 /__kshrd_502.html;
    location = /__kshrd_502.html {
        internal;
        alias html/502.html;
        ssi on;
    }
"@
    }
    $head = if ($upstreams) { ($upstreams -join "`n`n") + "`n`n" } else { '' }
    "${head}server {`n$tls`n`n$($locations -join "`n`n")`n}"
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

function Get-StatusRows([string]$Filter) {
    $sites = Get-Sites
    foreach ($hostname in $sites.Keys) {
        $routes = Get-Routes $sites[$hostname]
        if ($routes.Count -eq 0) {
            $rows = @([pscustomobject]@{ url = "https://$hostname"; kind = 'placeholder'; target = 'placeholder page'; up = $null })
        } else {
            $rows = foreach ($path in $routes.Keys) {
                $stored = $routes[$path]
                [pscustomobject]@{
                    url    = "https://$hostname$(if ($path -ne '/') { $path })"
                    kind   = Get-TargetKind $stored
                    target = Get-TargetText $stored
                    up     = [bool](Test-Target $stored)
                }
            }
        }
        $rows | Where-Object { -not $Filter -or $_.url.Contains($Filter.ToLowerInvariant()) }
    }
}

function Show-Status {
    $running = Test-NginxRunning
    $rows = @(Get-StatusRows $Name)
    if ($Json) {
        [pscustomobject]@{ version = $AppVersion; nginx = $(if ($running) { 'running' } else { 'stopped' }); sites = $rows } | ConvertTo-Json -Depth 4
        return
    }
    Write-Host 'nginx: ' -NoNewline
    if ($running) { Write-Color 'running' 'Green' } else { Write-Color 'stopped' 'Red' }
    if (-not $rows) {
        if ($Name) { Write-Host "No sites match '$Name'." } else { Write-Host "No sites yet. Run 'kshrd setup'." }
        return
    }
    $cells = foreach ($row in $rows) {
        $state, $color = if ($null -eq $row.up) { '-', 'DarkGray' }
                         elseif ($row.up) { 'up', 'Green' }
                         elseif ($row.kind -eq 'dir') { 'MISSING', 'Red' }
                         else { 'DOWN', 'Red' }
        , @((New-Cell $row.url 'Cyan'), (New-Cell $row.target ''), (New-Cell $state $color))
    }
    Write-Table @('Site', 'Target', 'App') $cells
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
    if ($Clear) {
        foreach ($path in $access, $errorLog) {
            if (-not (Test-Path $path)) { continue }
            # nginx keeps these open, so empty them rather than delete them.
            $stream = [IO.FileStream]::new($path, 'Open', 'Write', [IO.FileShare]'ReadWrite, Delete')
            try { $stream.SetLength(0) } finally { $stream.Dispose() }
        }
        Write-Done "Cleared the logs for $hostname."
        return
    }
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
    $script:DoctorRows += , @((New-Cell $label.Trim() $color), (New-Cell $Message ''), (New-Cell $Fix 'Cyan'))
}

function Invoke-Doctor {
    $script:DoctorFailures = 0
    $script:DoctorWarnings = 0
    $script:DoctorRows = @()

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
        $routes = Get-Routes $sites[$hostname]
        $broken = @($routes.Keys | Where-Object { -not (Test-Target $routes[$_]) })
        foreach ($path in $broken) {
            $shown = "$hostname$(if ($path -ne '/') { $path })"
            $where = Get-TargetText $routes[$path]
            if ((Get-TargetKind $routes[$path]) -eq 'dir') {
                Write-Check warn "$shown serves a missing folder: $where" "create the folder, or change it with: kshrd add $hostname $(if ($path -ne '/') { "$path " })<target>"
            } else {
                Write-Check warn "$shown has nothing responding at $where" "start the app, or change it with: kshrd add $hostname $(if ($path -ne '/') { "$path " })<target>"
            }
        }
        if (-not $broken -and $addresses) {
            Write-Check ok "$hostname is working$(if (-not $running) { ' (HTTPS not checked: nginx is stopped)' })"
        }
    }

    foreach ($log in Get-ChildItem $LogDir -Filter '*.log' -ErrorAction SilentlyContinue) {
        if ($log.Length -gt $LogWarnBytes) {
            $site = $log.Name -replace '\.(access|error)\.log$', ''
            $fix = if ($site -eq $log.Name) { "stop nginx, then delete $($log.Name)" } else { "kshrd logs $site -Clear" }
            Write-Check warn ("{0} is {1:N0} MB" -f $log.Name, ($log.Length / 1MB)) $fix
        }
    }

    $autostart = Get-AutostartCommand
    if ($autostart -and -not $autostart.Contains("`"$PSCommandPath`"")) {
        Write-Check warn 'autostart points at a different copy of kshrd' 'kshrd autostart on'
    }

    Write-Table @('Status', 'Check', 'Fix') $script:DoctorRows
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

function Split-SiteSpec([string]$Spec) {
    # 'seyha.com/api' -> host seyha.com, path /api
    $slash = $Spec.IndexOf('/')
    if ($slash -lt 0) { return [pscustomobject]@{ Hostname = Resolve-Hostname $Spec; Path = $null } }
    [pscustomobject]@{
        Hostname = Resolve-Hostname $Spec.Substring(0, $slash)
        Path     = ConvertTo-RoutePath $Spec.Substring($slash)
    }
}

function New-AddItem([string]$Spec, [string]$RoutePath, [string]$TargetText, [string]$BaseDir) {
    $site = Split-SiteSpec $Spec
    $path = if ($RoutePath) { ConvertTo-RoutePath $RoutePath } elseif ($site.Path) { $site.Path } else { '/' }
    [pscustomobject]@{ Hostname = $site.Hostname; Path = $path; Stored = ConvertTo-StoredTarget $TargetText $BaseDir }
}

function Get-AddItems {
    $usage = 'usage: kshrd add <name> <target>, kshrd add <name> /path <target>, or kshrd add <name>:<target> <name>:<target> ...'
    if (-not $Name) { Fail $usage }
    $base = (Get-Location).Path
    if ($Name.Contains(':')) {
        foreach ($spec in @($Name, $Target) + @($Rest) | Where-Object { $_ }) {
            $parts = $spec -split ':', 2
            if ($parts.Count -ne 2) { Fail "'$spec' needs a target, as in name:3000. $usage" }
            New-AddItem $parts[0] '' $parts[1] $base
        }
    } elseif ($Target -and $Target.StartsWith('/') -and @($Rest).Count -eq 1) {
        New-AddItem $Name $Target $Rest[0] $base
    } elseif ($Target -and -not @($Rest).Count) {
        New-AddItem $Name '' $Target $base
    } else {
        Fail $usage
    }
}

function Add-Items($Items, [switch]$NoPrompt) {
    if (-not (Test-Path (Join-Path $CertDir "$Domain.pem"))) { Fail "run 'kshrd setup' first." }
    $sites = Get-Sites
    if (-not $NoPrompt) {
        $checked = @()
        foreach ($item in $Items) {
            if (-not $sites.Contains($item.Hostname) -and $item.Hostname -notin $checked) {
                $checked += $item.Hostname
                if ((Test-RealDomain $item.Hostname) -and -not (Confirm-Action "$($item.Hostname) is a real site on the internet. This PC can't reach the real one while this entry exists.")) {
                    Fail 'cancelled; nothing was changed.'
                }
            }
            # Repeating a mapping that already exists doesn't need asking about again.
            $existing = (Get-Routes $sites[$item.Hostname])[$item.Path]
            if ("$existing" -ne "$($item.Stored)" -and -not (Test-Target $item.Stored)) {
                if (-not (Confirm-Action "Nothing is responding at $(Get-TargetText $item.Stored). Check it isn't a typo.")) {
                    Fail 'cancelled; nothing was changed.'
                }
            }
        }
    }
    foreach ($item in $Items) {
        $routes = Get-Routes $sites[$item.Hostname]
        $routes[$item.Path] = $item.Stored
        $sites[$item.Hostname] = Compress-Routes $routes
    }
    New-OwnCerts $sites
    Set-Sites $sites
    foreach ($item in $Items) {
        Write-Color "https://$($item.Hostname)$(if ($item.Path -ne '/') { $item.Path })" 'Cyan' -NoNewline
        Write-Host " -> $(Get-TargetText $item.Stored)"
    }
}

function Invoke-Add {
    Add-Items @(Get-AddItems)
}

function Remove-Items($Items, [switch]$IgnoreMissing) {
    $sites = Get-Sites
    $gone = @()
    $done = @()
    foreach ($item in $Items) {
        $hostname = $item.Hostname
        if (-not $sites.Contains($hostname)) {
            if ($IgnoreMissing) { continue }
            Fail "$hostname is not registered."
        }
        $routes = Get-Routes $sites[$hostname]
        if ($item.Path) {
            if (-not $routes.Contains($item.Path)) {
                if ($IgnoreMissing) { continue }
                Fail "$hostname has no route for $($item.Path)."
            }
            $routes.Remove($item.Path)
            $done += "$hostname$($item.Path)"
        } else {
            $routes.Clear()
            $done += $hostname
        }
        if ($routes.Count) {
            $sites[$hostname] = Compress-Routes $routes
        } elseif ($hostname -eq $Domain) {
            # The bare domain stays registered and falls back to the placeholder page.
            $sites[$Domain] = $null
        } else {
            $sites.Remove($hostname)
            $gone += $hostname
        }
    }
    if (-not $done) { Write-Host 'Nothing to remove.'; return }
    Set-Sites $sites
    foreach ($hostname in $gone) {
        if (Test-OwnCert $hostname) {
            Remove-Item (Join-Path $CertDir "$hostname.pem"), (Join-Path $CertDir "$hostname-key.pem") -Force -ErrorAction SilentlyContinue
        }
        # A worker that is still finishing may hold these open, so this is best effort.
        Remove-Item (Join-Path $LogDir "$hostname.access.log"), (Join-Path $LogDir "$hostname.error.log") -Force -ErrorAction SilentlyContinue
    }
    foreach ($entry in $done) { Write-Done "Removed $entry." }
}

function Invoke-Remove {
    if (-not $Name) { Fail 'usage: kshrd remove <name> [/path], or kshrd remove <name> <name> ...' }
    if ($Target -and $Target.StartsWith('/')) {
        if (@($Rest).Count) { Fail 'usage: kshrd remove <name> /path' }
        Remove-Items @([pscustomobject]@{ Hostname = Resolve-Hostname $Name; Path = ConvertTo-RoutePath $Target })
        return
    }
    $items = foreach ($spec in @($Name, $Target) + @($Rest) | Where-Object { $_ }) { Split-SiteSpec $spec }
    Remove-Items @($items)
}

function Read-ProjectItems {
    # kshrd.json: { "sites": { "shop.test": 3000, "shop.test/api": 5000, "docs.test": "./dist" } }
    $base = (Get-Location).Path
    $path = Join-Path $base $ProjectFile
    if (-not (Test-Path $path)) { Fail "no $ProjectFile in $base. See 'kshrd help up'." }
    try {
        $project = Get-Content $path -Raw | ConvertFrom-Json
    } catch {
        Fail "$ProjectFile is not valid JSON: $($_.Exception.Message)"
    }
    $entries = @($project.sites.PSObject.Properties)
    if (-not $entries) { Fail "$ProjectFile has no sites. It needs: { `"sites`": { `"shop.test`": 3000 } }" }
    foreach ($entry in $entries) {
        New-AddItem $entry.Name '' "$($entry.Value)" $base
    }
}

function Invoke-Up {
    # A project file is written on purpose, and its apps usually start afterwards, so no questions.
    $items = @(Read-ProjectItems)
    Add-Items $items -NoPrompt
}

function Invoke-Down {
    $items = @(Read-ProjectItems)
    Remove-Items $items -IgnoreMissing
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
        Usage    = 'kshrd add <name> [/path] <target> [-Yes]'
        Summary  = 'Point a site or path at an app, machine or folder, or change it'
        Details  = "<name> is a subdomain, $Domain for the main site, or a full custom domain, which gets its own certificate. <target> is a local port, a host:port on another machine, or a folder to serve. A /path route keeps the path when it calls the app, so /api/users arrives as /api/users. Several name:target pairs can be added at once with one admin prompt. kshrd asks first if the name is a real website or nothing responds at the target; -Yes skips the question. Prefer the reserved .test ending for made-up names."
        Examples = @(
            @('kshrd add shop.test 3000', 'https://shop.test -> localhost:3000'),
            @('kshrd add demo 3000', "https://demo.$Domain -> localhost:3000"),
            @("kshrd add $Domain 3000", "https://$Domain -> localhost:3000"),
            @('kshrd add shop.test /api 5000', 'https://shop.test/api -> localhost:5000'),
            @('kshrd add docs.test ./dist', 'https://docs.test -> the dist folder'),
            @('kshrd add db.test 192.168.1.5:8080', 'https://db.test -> another machine'),
            @('kshrd add a.test:3000 api.a.test:5000', 'Add both with one admin prompt')
        )
    }
    up       = @{
        Usage    = 'kshrd up'
        Summary  = "Add every site listed in this folder's kshrd.json"
        Details  = 'kshrd.json looks like { "sites": { "shop.test": 3000, "shop.test/api": 5000, "docs.test": "./dist" } }. Folders are relative to it. Run it again after editing the file. Removing a line does not remove the site, so run kshrd down before you remove one.'
        Examples = @(, @('kshrd up', 'Add this project''s sites'))
    }
    down     = @{
        Usage    = 'kshrd down'
        Summary  = "Remove every site listed in this folder's kshrd.json"
        Details  = 'Only removes what the file lists. Other routes on the same site stay.'
        Examples = @(, @('kshrd down', 'Remove this project''s sites'))
    }
    remove   = @{
        Usage    = 'kshrd remove <name> [/path]'
        Summary  = 'Remove a site, several sites, or one path'
        Details  = "A custom domain's certificate is deleted too. Removing $Domain keeps it registered and brings back the placeholder page."
        Examples = @(
            @('kshrd remove shop.test', 'Stop serving https://shop.test'),
            @('kshrd remove demo', "Stop serving https://demo.$Domain"),
            @('kshrd remove shop.test /api', 'Remove only the /api route'),
            @('kshrd remove a.test b.test', 'Remove both with one admin prompt')
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
        Usage    = 'kshrd logs <name> [-Follow] [-Errors] [-Clear]'
        Summary  = 'Show the recent requests and errors for one site'
        Details  = 'Shows the last 30 lines of each log. -Follow (or -f) keeps watching the requests until you press Ctrl+C. -Errors shows only the errors, and can be combined with -Follow. -Clear empties both logs.'
        Examples = @(
            @('kshrd logs shop.test', 'Show recent requests and errors'),
            @('kshrd logs shop.test -f', 'Watch requests as they arrive'),
            @('kshrd logs shop.test -Errors', 'Show only the errors'),
            @('kshrd logs shop.test -Clear', 'Empty the logs')
        )
    }
    list     = @{
        Usage    = 'kshrd list [filter] [-Json]'
        Summary  = 'Show nginx, each site, and whether its app is up'
        Details  = 'Same as kshrd status. [filter] keeps sites whose URL contains that text. -Json prints the result for other scripts.'
        Examples = @(
            @('kshrd list', 'Show all sites'),
            @('kshrd list seyha', 'Show only matching sites'),
            @('kshrd list -Json', 'Print as JSON')
        )
    }
    status   = @{
        Usage    = 'kshrd status [filter] [-Json]'
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
    $rows = foreach ($example in $Examples) { , @((New-Cell $example[0] 'Green'), (New-Cell $example[1] '')) }
    Write-Table @('Command', 'Result') $rows
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
    $rows = foreach ($key in $HelpTopics.Keys) {
        , @((New-Cell $HelpTopics[$key].Usage.Substring(6) 'Cyan'), (New-Cell $HelpTopics[$key].Summary ''))
    }
    Write-Table @('Command', 'What it does') $rows
    Write-Host ''
    Write-Heading 'Names:'
    Write-Table @('Name', 'Meaning') @(
        , @((New-Cell 'demo' 'Cyan'), (New-Cell "A subdomain: https://demo.$Domain" ''))
        , @((New-Cell $Domain 'Cyan'), (New-Cell 'The main site' ''))
        , @((New-Cell 'shop.test' 'Cyan'), (New-Cell 'A custom domain, used exactly as written, with its own certificate' ''))
        , @((New-Cell 'api.shop.test' 'Cyan'), (New-Cell 'A subdomain of a custom domain. Add each one by its full name' ''))
    )
    Write-Host ''
    Write-Heading 'Targets:'
    Write-Table @('Target', 'Meaning') @(
        , @((New-Cell '3000' 'Cyan'), (New-Cell 'An app on this PC, at localhost:3000' ''))
        , @((New-Cell '192.168.1.5:8080' 'Cyan'), (New-Cell 'An app on another machine' ''))
        , @((New-Cell './dist' 'Cyan'), (New-Cell 'A folder of files to serve' ''))
    )
    Write-Host ''
    Write-Examples @(
        @('kshrd setup', 'First run on this PC'),
        @('kshrd add shop.test 3000', 'https://shop.test -> localhost:3000'),
        @('kshrd add demo 3000', "https://demo.$Domain -> localhost:3000"),
        @('kshrd add shop.test /api 5000', 'https://shop.test/api -> localhost:5000'),
        @('kshrd add docs.test ./dist', 'https://docs.test -> the dist folder'),
        @('kshrd add db.test 192.168.1.5:8080', 'https://db.test -> another machine'),
        @('kshrd add a.test:3000 b.test:4000', 'Add both with one admin prompt'),
        @('kshrd up', "Add the sites in this folder's kshrd.json"),
        @('kshrd open shop.test', 'Open it in the browser'),
        @('kshrd logs shop.test -f', 'Watch its requests'),
        @('kshrd logs shop.test -Clear', 'Empty its logs'),
        @('kshrd list', 'Check nginx and each site'),
        @('kshrd list shop', 'Show only the sites matching shop'),
        @('kshrd doctor', 'Find out why something is not working'),
        @('kshrd remove shop.test', 'Remove a site'),
        @('kshrd remove shop.test /api', 'Remove only the /api route'),
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
    'up'           { Invoke-Up }
    'down'         { Invoke-Down }
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
