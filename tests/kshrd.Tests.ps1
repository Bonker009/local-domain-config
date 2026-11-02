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
