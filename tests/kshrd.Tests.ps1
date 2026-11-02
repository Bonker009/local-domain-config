# Run with: Invoke-Pester .\tests
# These tests never touch the real hosts file, nginx or certs/.
$script = Join-Path $PSScriptRoot '..\kshrd.ps1'
. $script help

function Invoke-Kshrd {
    $output = & pwsh -NoProfile -File $script @args 2>&1 | Out-String
    [pscustomobject]@{ Output = $output; ExitCode = $LASTEXITCODE }
}

Describe 'Resolve-Hostname' {
    It 'turns a bare name into a subdomain' { Resolve-Hostname 'demo' | Should Be 'demo.kshrd.app' }
    It 'keeps the main domain' { Resolve-Hostname 'kshrd.app' | Should Be 'kshrd.app' }
    It 'treats @ as the main domain' { Resolve-Hostname '@' | Should Be 'kshrd.app' }
    It 'keeps a custom domain' { Resolve-Hostname 'shop.test' | Should Be 'shop.test' }
    It 'lowercases names' { Resolve-Hostname 'Shop.TEST' | Should Be 'shop.test' }
}

Describe 'Invalid names' {
    # 'remove' checks the name before it changes anything.
    foreach ($name in 'bad_name.test', '*.shop.test', 'foo.localhost', '1.2.3.4', 'a..b') {
        It "rejects $name" {
            $result = Invoke-Kshrd remove $name
            $result.ExitCode | Should Be 1
            $result.Output | Should Match 'error:'
        }
    }
}

Describe 'Test-OwnCert' {
    It 'uses the shared certificate for the main domain' { Test-OwnCert 'kshrd.app' | Should Be $false }
    It 'uses the shared certificate for one label below it' { Test-OwnCert 'demo.kshrd.app' | Should Be $false }
    It 'needs its own for two labels below it' { Test-OwnCert 'a.b.kshrd.app' | Should Be $true }
    It 'needs its own for a custom domain' { Test-OwnCert 'shop.test' | Should Be $true }
    It 'is not fooled by a lookalike domain' { Test-OwnCert 'notkshrd.app' | Should Be $true }
}

Describe 'New-SiteConfig' {
    It 'proxies a port with both loopback families' {
        $config = New-SiteConfig 'demo.kshrd.app' 3000
        $config | Should Match 'server 127\.0\.0\.1:3000'
        $config | Should Match 'server \[::1\]:3000'
        $config | Should Match 'listen 127\.0\.0\.2:443 ssl'
    }
    It 'adds a certificate only for a custom domain' {
        New-SiteConfig 'shop.test' 3000 | Should Match 'certs/shop\.test\.pem'
        New-SiteConfig 'demo.kshrd.app' 3000 | Should Not Match 'ssl_certificate'
    }
    It 'serves the placeholder without a port' {
        $config = New-SiteConfig 'kshrd.app' $null
        $config | Should Match 'root html'
        $config | Should Not Match 'proxy_pass'
    }
}

Describe 'Get-HostsContent' {
    $HostsFile = Join-Path $TestDrive 'hosts'
    $block = "# BEGIN kshrd.app`r`n127.0.0.2 old.kshrd.app`r`n# END kshrd.app`r`n"
    $original = "127.0.0.1 localhost`r`n# 127.0.0.1 commented.kshrd.app`r`n"

    It 'keeps other lines and adds a block' {
        [IO.File]::WriteAllText($HostsFile, $original)
        $result = Get-HostsContent @('demo.kshrd.app')
        $result | Should Match '127\.0\.0\.1 localhost'
        $result | Should Match '127\.0\.0\.2 demo\.kshrd\.app'
    }
    It 'replaces an existing block' {
        [IO.File]::WriteAllText($HostsFile, $original + $block)
        $result = Get-HostsContent @('demo.kshrd.app')
        $result | Should Not Match 'old\.kshrd\.app'
        ([regex]::Matches($result, 'BEGIN kshrd\.app')).Count | Should Be 1
    }
    It 'restores the original text when clearing' {
        [IO.File]::WriteAllText($HostsFile, $original + $block)
        Get-HostsContent @() | Should BeExactly $original
    }
    It 'ignores a commented-out line for the same name' {
        [IO.File]::WriteAllText($HostsFile, $original)
        Get-HostsContent @('commented.kshrd.app') | Should Match '127\.0\.0\.2 commented\.kshrd\.app'
    }
    It 'does not add a name mapped elsewhere' {
        [IO.File]::WriteAllText($HostsFile, "127.0.0.1 taken.kshrd.app`r`n")
        Get-HostsContent @('taken.kshrd.app') 3>$null | Should Not Match '127\.0\.0\.2'
    }
}

Describe 'Command line' {
    foreach ($form in 'version', '--version', '-v') {
        It "prints the version for $form" {
            $result = Invoke-Kshrd $form
            $result.ExitCode | Should Be 0
            $result.Output | Should Match '^kshrd \d+\.\d+\.\d+'
        }
    }
    It 'lists commands in help' { (Invoke-Kshrd help).Output | Should Match 'Commands:' }
    It 'fails on an unknown command' { (Invoke-Kshrd nonsense).ExitCode | Should Be 1 }
}

Describe 'Test-CertNeedsRenewal' {
    $CertDir = $TestDrive

    function New-TestCert([string]$BaseName, [int]$Days, [switch]$NoKey) {
        $rsa = [Security.Cryptography.RSA]::Create(2048)
        $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=$BaseName", $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $now = [DateTimeOffset]::Now
        $cert = $request.CreateSelfSigned($now.AddDays(-400), $now.AddDays($Days))
        [IO.File]::WriteAllText((Join-Path $TestDrive "$BaseName.pem"), $cert.ExportCertificatePem())
        if (-not $NoKey) { [IO.File]::WriteAllText((Join-Path $TestDrive "$BaseName-key.pem"), 'key') }
    }

    It 'keeps a certificate with plenty of time left' {
        New-TestCert 'fresh' 200
        Test-CertNeedsRenewal 'fresh' | Should Be $false
    }
    It 'renews one that expires soon' {
        New-TestCert 'soon' 10
        Test-CertNeedsRenewal 'soon' | Should Be $true
    }
    It 'renews an expired one' {
        New-TestCert 'expired' -5
        Test-CertNeedsRenewal 'expired' | Should Be $true
    }
    It 'renews when the certificate is missing' {
        Test-CertNeedsRenewal 'absent' | Should Be $true
    }
    It 'renews when the key is missing' {
        New-TestCert 'nokey' 200 -NoKey
        Test-CertNeedsRenewal 'nokey' | Should Be $true
    }
    It 'renews when the file is not a certificate' {
        [IO.File]::WriteAllText((Join-Path $TestDrive 'junk.pem'), 'not a certificate')
        [IO.File]::WriteAllText((Join-Path $TestDrive 'junk-key.pem'), 'key')
        Test-CertNeedsRenewal 'junk' | Should Be $true
    }
}

Describe 'Get-CertTargets' {
    $sites = [ordered]@{ 'kshrd.app' = $null; 'demo.kshrd.app' = 3000; 'shop.test' = 4000 }
    $targets = @(Get-CertTargets $sites)
    It 'has the shared certificate and one per custom domain' {
        ($targets.BaseName -join ',') | Should Be 'kshrd.app,shop.test'
    }
    It 'covers subdomains with the shared certificate' {
        $targets[0].Names -contains '*.kshrd.app' | Should Be $true
    }
}

Describe 'Get-HostsAddresses' {
    $text = "127.0.0.1 a.test b.test``
# 127.0.0.2 c.test``
127.0.0.2 d.test # 127.0.0.9 e.test``
"
    It 'finds a name anywhere on the line' { Get-HostsAddresses 'b.test' $text | Should Be '127.0.0.1' }
    It 'ignores commented lines' { Get-HostsAddresses 'c.test' $text | Should BeNullOrEmpty }
    It 'ignores trailing comments' { Get-HostsAddresses 'e.test' $text | Should BeNullOrEmpty }
    It 'does not match the address itself' { Get-HostsAddresses '127.0.0.1' $text | Should BeNullOrEmpty }
}

Describe 'Per-site logs' {
    It 'gives a proxied site its own logs' {
        $config = New-SiteConfig 'shop.test' 3000
        $config | Should Match 'access_log logs/shop\.test\.access\.log'
        $config | Should Match 'error_log logs/shop\.test\.error\.log'
    }
    It 'gives the placeholder site its own logs' {
        New-SiteConfig 'kshrd.app' $null | Should Match 'access_log logs/kshrd\.app\.access\.log'
    }
}

Describe 'Commands that need a registered site' {
    foreach ($command in 'open', 'logs') {
        It "$command rejects an unregistered name" {
            $result = Invoke-Kshrd $command 'no-such-site.test'
            $result.ExitCode | Should Be 1
            $result.Output | Should Match 'not registered'
        }
    }
    It 'autostart rejects an unknown action' {
        (Invoke-Kshrd autostart maybe).ExitCode | Should Be 1
    }
}

Describe 'kshrd logs sections' {
    # kshrd.app is always registered, and reading its logs changes nothing.
    It 'shows both sections by default' {
        $output = (Invoke-Kshrd logs kshrd.app).Output
        $output | Should Match '== Requests =='
        $output | Should Match '== Errors =='
    }
    It 'shows only errors with -Errors' {
        $output = (Invoke-Kshrd logs kshrd.app -Errors).Output
        $output | Should Match '== Errors =='
        $output | Should Not Match '== Requests =='
    }
}

Describe 'Colour' {
    Mock Write-Host {}

    It 'uses the colour by default' {
        $env:NO_COLOR = $null
        Write-Color 'text' 'Green'
        Assert-MockCalled Write-Host -Exactly 1 -Scope It -ParameterFilter { $ForegroundColor -eq 'Green' }
    }
    It 'drops the colour when NO_COLOR is set' {
        $env:NO_COLOR = '1'
        Write-Color 'text' 'Green'
        $env:NO_COLOR = $null
        Assert-MockCalled Write-Host -Exactly 0 -Scope It -ParameterFilter { $ForegroundColor }
        Assert-MockCalled Write-Host -Exactly 1 -Scope It
    }
    It 'writes plain text when no colour is given' {
        Write-Color 'text' ''
        Assert-MockCalled Write-Host -Exactly 0 -Scope It -ParameterFilter { $ForegroundColor }
    }
    foreach ($case in @(
        @('127.0.0.1 - - [x] "GET / HTTP/1.1" 500 10 "-" "c"', 'Red'),
        @('127.0.0.1 - - [x] "GET / HTTP/1.1" 404 10 "-" "c"', 'Yellow'),
        @('2026/11/02 12:00:00 [error] 1#1: failed', 'Red'),
        @('2026/11/02 12:00:00 [warn] 1#1: careful', 'Yellow')
    )) {
        It "colours a log line as $($case[1]): $($case[0])" {
            $expected = $case[1]
            Write-LogLine $case[0]
            Assert-MockCalled Write-Host -Exactly 1 -Scope It -ParameterFilter { $ForegroundColor -eq $expected }
        }
    }
    It 'leaves a successful request uncoloured' {
        Write-LogLine '127.0.0.1 - - [x] "GET / HTTP/1.1" 200 10 "-" "c"'
        Assert-MockCalled Write-Host -Exactly 0 -Scope It -ParameterFilter { $ForegroundColor }
    }
}

Describe 'Redirected output' {
    It 'contains no colour codes' {
        (Invoke-Kshrd help).Output | Should Not Match ([char]27)
    }
}

Describe 'Split-TextToWidth' {
    It 'keeps short text on one line' { @(Split-TextToWidth 'short text' 20).Count | Should Be 1 }
    It 'wraps on spaces' { (@(Split-TextToWidth 'one two three' 7) -join '|') | Should Be 'one two|three' }
    It 'breaks a word longer than the line' { (@(Split-TextToWidth 'abcdefghij' 4) -join '|') | Should Be 'abcd|efgh|ij' }
    It 'returns one empty line for empty text' { @(Split-TextToWidth '' 5).Count | Should Be 1 }
}

Describe 'Get-ColumnWidths' {
    It 'keeps widths that already fit' { (Get-ColumnWidths @(10, 20) 100) -join ',' | Should Be '10,20' }
    It 'shrinks the widest column first' { (Get-ColumnWidths @(10, 80) 60) -join ',' | Should Be '10,43' }
    It 'never shrinks below the minimum' { (Get-ColumnWidths @(30, 30) 5) -join ',' | Should Be '8,8' }
}

Describe 'Write-Table' {
    $script:lines = @()
    $script:current = ''
    Mock Write-Host {
        $script:current += "$Object"
        if (-not $NoNewline) { $script:lines += $script:current; $script:current = '' }
    }
    $rows = @(, @((New-Cell 'a long piece of text that must wrap' ''), (New-Cell 'x' 'Green')))
    Write-Table @('First', 'Second') $rows -MaxWidth 30

    It 'draws every line the same width, within the limit' {
        ($script:lines | ForEach-Object { $_.Length } | Sort-Object -Unique) -join ',' | Should Be '30'
    }
    It 'keeps all the text' {
        (($script:lines | Where-Object { $_ -like '|*' } | ForEach-Object { ($_ -split '\|')[1].Trim() }) -join ' ') | Should Match 'a long piece of text that must wrap'
    }
    It 'handles an unwrapped single row, as a foreach produces' {
        $script:lines = @()
        $single = foreach ($n in 'only') { , @((New-Cell $n ''), (New-Cell 'value' '')) }
        Write-Table @('A', 'B') $single -MaxWidth 30
        ($script:lines -join ' ') | Should Match '\| only \| value'
    }
    It 'handles a single row and a single column' {
        $script:lines = @()
        Write-Table @('Only') @(, @(, (New-Cell 'one' ''))) -MaxWidth 30
        ($script:lines -join ' ') | Should Match '\| one'
    }
}

Describe 'Help tables' {
    It 'shows a command with one example' {
        (Invoke-Kshrd help setup).Output | Should Match '\| kshrd setup \| Prepare this PC'
    }
}

Describe 'ConvertTo-StoredTarget' {
    It 'stores a port as a number' { ConvertTo-StoredTarget '3000' $TestDrive | Should Be 3000 }
    It 'treats localhost:port as a port' { ConvertTo-StoredTarget 'localhost:3000' $TestDrive | Should Be 3000 }
    It 'keeps another machine as host:port' { ConvertTo-StoredTarget '192.168.1.5:8080' $TestDrive | Should Be '192.168.1.5:8080' }
    It 'accepts a bracketed IPv6 address' { ConvertTo-StoredTarget '[fd00::1]:8080' $TestDrive | Should Be '[fd00::1]:8080' }
    It 'resolves a relative folder' {
        New-Item -ItemType Directory (Join-Path $TestDrive 'dist') | Out-Null
        ConvertTo-StoredTarget './dist' $TestDrive | Should Match '^dir:.*/dist$'
    }
}

Describe 'Invalid targets and routes' {
    # All of these fail before anything changes.
    It 'rejects a port out of range' { (Invoke-Kshrd add x.test 99999).Output | Should Match 'between 1 and 65535' }
    It 'rejects nginx''s own port' { (Invoke-Kshrd add x.test 443).Output | Should Match 'used by nginx' }
    It 'rejects a missing folder' { (Invoke-Kshrd add x.test ./no-such-folder).Output | Should Match 'existing folder' }
    It 'rejects a path with ..' { (Invoke-Kshrd add x.test /a/../b 3000).Output | Should Match 'not a valid path' }
    It 'rejects a path with odd characters' { (Invoke-Kshrd add x.test '/a;b' 3000).Output | Should Match 'not a valid path' }
    It 'rejects a batch item with no target' { (Invoke-Kshrd add a.test:3000 b.test).Output | Should Match 'needs a target' }
    It 'rejects add with no target' { (Invoke-Kshrd add x.test).ExitCode | Should Be 1 }
    It 'fails on an unregistered route' { (Invoke-Kshrd remove no-such.test /api).ExitCode | Should Be 1 }
}

Describe 'Get-Routes and Compress-Routes' {
    It 'has no routes for a placeholder' { (Get-Routes $null).Count | Should Be 0 }
    It 'reads a plain port as the root route' { (Get-Routes 3000)['/'] | Should Be 3000 }
    It 'reads routes loaded from JSON' {
        $routes = Get-Routes ('{"/":3000,"/api":5000}' | ConvertFrom-Json)
        $routes['/api'] | Should Be 5000
        $routes.Count | Should Be 2
    }
    It 'stores a single root route as a plain value' {
        $routes = [ordered]@{ '/' = 3000 }
        Compress-Routes $routes | Should Be 3000
    }
    It 'keeps several routes' {
        $routes = [ordered]@{ '/' = 3000; '/api' = 5000 }
        (Compress-Routes $routes).Count | Should Be 2
    }
    It 'has nothing to store for no routes' {
        Compress-Routes ([ordered]@{}) | Should BeNullOrEmpty
    }
}

Describe 'Split-SiteSpec' {
    It 'finds a host' {
        $site = Split-SiteSpec 'shop.test'
        $site.Hostname | Should Be 'shop.test'
        $site.Path | Should BeNullOrEmpty
    }
    It 'finds a host and path, without a trailing slash' {
        $site = Split-SiteSpec 'shop.test/api/'
        $site.Hostname | Should Be 'shop.test'
        $site.Path | Should Be '/api'
    }
}

Describe 'New-SiteConfig routes' {
    $config = New-SiteConfig 'shop.test' ([ordered]@{ '/' = 3000; '/api' = 5000 })
    It 'has one upstream per route' {
        $config | Should Match 'upstream shop\.test\.upstream \{'
        $config | Should Match 'upstream shop\.test\.upstream1 \{'
    }
    It 'matches a path with and without its slash' {
        $config | Should Match 'location = /api \{'
        $config | Should Match 'location /api/ \{'
    }
    It 'keeps the path when calling the app' {
        $config | Should Match 'proxy_pass http://shop\.test\.upstream1;'
    }
    It 'adds no catch-all when / is routed' { $config | Should Not Match 'return 404' }

    It 'returns 404 for other paths when / is not routed' {
        New-SiteConfig 'shop.test' ([ordered]@{ '/api' = 5000 }) | Should Match 'return 404'
    }
    It 'serves a folder at the root' {
        $folder = New-SiteConfig 'docs.test' 'dir:D:/site/dist'
        $folder | Should Match 'root "D:/site/dist"'
        $folder | Should Not Match 'proxy_pass'
        $folder | Should Not Match '__kshrd_502'
    }
    It 'serves a folder at a path' {
        $folder = New-SiteConfig 'docs.test' ([ordered]@{ '/docs' = 'dir:D:/site' })
        $folder | Should Match 'alias "D:/site/"'
        $folder | Should Match 'return 301 /docs/'
    }
    It 'proxies another machine with no loopback fallback' {
        $remote = New-SiteConfig 'db.test' '192.168.1.5:8080'
        $remote | Should Match 'server 192\.168\.1\.5:8080 '
        $remote | Should Not Match '::1'
    }
}

Describe 'Test-RealDomain' {
    Mock Resolve-DnsName { [pscustomobject]@{ Type = 'A' } }
    It 'is true for a name DNS knows' { Test-RealDomain 'seyha.com' | Should Be $true }
    It 'skips private endings without asking DNS' {
        Test-RealDomain 'shop.test' | Should Be $false
        Assert-MockCalled Resolve-DnsName -Exactly 0 -Scope It
    }
    It 'skips names under the shared domain' { Test-RealDomain 'demo.kshrd.app' | Should Be $false }
    It 'is false when DNS has no answer' {
        Mock Resolve-DnsName { throw 'no such name' }
        Test-RealDomain 'nothing-here.example.com' | Should Be $false
    }
}

Describe 'Project file errors' {
    $here = Get-Location
    BeforeEach { Set-Location $TestDrive }
    AfterEach { Set-Location $here }
    It 'fails without a file' {
        Remove-Item (Join-Path $TestDrive 'kshrd.json') -ErrorAction SilentlyContinue
        (Invoke-Kshrd up).Output | Should Match 'no kshrd\.json'
    }
    It 'fails on invalid JSON' {
        [IO.File]::WriteAllText((Join-Path $TestDrive 'kshrd.json'), '{ nope')
        (Invoke-Kshrd up).Output | Should Match 'not valid JSON'
    }
    It 'fails with no sites' {
        [IO.File]::WriteAllText((Join-Path $TestDrive 'kshrd.json'), '{ "sites": {} }')
        (Invoke-Kshrd down).Output | Should Match 'has no sites'
    }
}

Describe 'List output' {
    It 'prints valid JSON' {
        $data = (Invoke-Kshrd list -Json).Output | ConvertFrom-Json
        $data.version | Should Match '^\d+\.\d+\.\d+'
        @($data.sites).Count -gt 0 | Should Be $true
    }
    It 'filters sites' {
        $output = (Invoke-Kshrd list no-site-has-this-name).Output
        $output | Should Match 'No sites match'
    }
}

Describe 'Main help' {
    $output = (Invoke-Kshrd help).Output
    It 'explains targets' { $output | Should Match 'Targets:' }
    It 'lists every command' {
        foreach ($command in 'setup', 'add', 'up', 'down', 'remove', 'open', 'logs', 'list', 'status', 'start', 'stop', 'restart', 'teardown', 'autostart', 'doctor', 'renew', 'version', 'help') {
            $output | Should Match "\| $command\b"
        }
    }
}
