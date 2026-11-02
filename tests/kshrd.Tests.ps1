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
