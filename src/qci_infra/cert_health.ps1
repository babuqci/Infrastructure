# Read-only TLS certificate probe, run on Windows VMs through Azure Run Command by
# `qci-infra cert-check`. Reads the W3SVC service state, IIS HTTPS bindings
# (applicationHost.config + `netsh http show sslcert`), the public metadata of the certs in
# LocalMachine\My and \WebHosting (never private keys), and certificate-renewal scheduled
# tasks. Creates, changes and deletes nothing. Each read is independent: a failure is
# reported in `gaps`. Output is ONE compact JSON line: Run Command keeps only ~4 KB.
$ErrorActionPreference = 'Stop'
$o = [ordered]@{ host = $env:COMPUTERNAME }
$gaps = New-Object System.Collections.ArrayList

function Short([string]$s, [int]$n) { if ($s.Length -gt $n) { $s.Substring(0, $n) } else { $s } }
function Gap($what, $err) { [void]$gaps.Add("${what}: " + (Short ($err.Exception.Message -replace '\s+', ' ') 150)) }
function Utc($d) { if ($d -and $d.Year -gt 1999) { $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }
function CN([string]$dn) { if ($dn -match 'CN=([^,]+)') { $Matches[1] } else { Short $dn 60 } }

try {
    $s = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    $o.iis = if ($s) { "$($s.Status)" } else { 'Missing' }
} catch { Gap 'w3svc' $_ }

$bound = @{}; $nohost = @{}; $hosts = New-Object System.Collections.ArrayList
if ($o.iis -and $o.iis -ne 'Missing') {
    try {
        # http.sys SSL bindings: "host:port" (SNI) or "ip:port" -> certificate hash
        $ssl = @{}; $key = $null
        foreach ($ln in (netsh http show sslcert)) {
            if ($ln -match '^\s*(Hostname:port|IP:port)\s*:\s*(\S+)') { $key = $Matches[2].ToLower() }
            elseif ($key -and $ln -match '^\s*Certificate Hash\s*:\s*([0-9a-fA-F]+)') { $ssl[$key] = $Matches[1].ToUpper(); $key = $null }
        }
        [xml]$x = Get-Content "$env:windir\System32\inetsrv\config\applicationHost.config"
        # Grouped per (site, cert) to keep the output small: h = "host" or "host:port" ("*" = no host header)
        $grp = [ordered]@{}
        foreach ($site in $x.configuration.'system.applicationHost'.sites.site) {
            foreach ($bd in @($site.bindings.binding)) {
                if ($bd.protocol -ne 'https') { continue }
                $ip, $port, $hn = $bd.bindingInformation -split ':', 3
                $ipk = if ($ip -eq '*' -or -not $ip) { '0.0.0.0' } else { $ip }
                $t = if ($hn -and $ssl["${hn}:$port".ToLower()]) { $ssl["${hn}:$port".ToLower()] }
                     elseif ($ssl["${ipk}:$port"]) { $ssl["${ipk}:$port"] } elseif ($ssl["[::]:$port"]) { $ssl["[::]:$port"] } else { '' }
                if ($t) { $bound[$t] = 1 }
                if ($hn) { [void]$hosts.Add($hn.ToLower()) } elseif ($t) { $nohost[$t] = 1 }
                $k = "$($site.name)|$t"
                if (-not $grp[$k]) { $grp[$k] = [ordered]@{ s = (Short $site.name 40); t = $t; h = New-Object System.Collections.ArrayList } }
                [void]$grp[$k].h.Add($(if ($hn) { $hn } else { '*' }) + $(if ($port -ne '443') { ":$port" } else { '' }))
            }
        }
        $o.b = @($grp.Values)
    } catch { Gap 'iis bindings' $_ }
}

function Covers([string]$n) {
    $n = $n.ToLower()
    foreach ($h in $hosts) {
        if ($n -eq $h -or ($n.StartsWith('*.') -and $h.EndsWith($n.Substring(1)) -and $h.Split('.').Count -eq $n.Split('.').Count)) { return $true }
    }
    $false
}

try {
    # Public metadata only, and only certs that matter to IIS: bound ones, and others valid for a
    # bound host name (a renewed cert left unbound). Names: those matching a binding host (all
    # names for a cert bound without host header), to fit Run Command's 4 KB.
    $all = foreach ($st in 'My', 'WebHosting') {
        if (-not (Test-Path "Cert:\LocalMachine\$st")) { continue }
        Get-ChildItem "Cert:\LocalMachine\$st" | ForEach-Object {
            $names = @($_.DnsNameList | ForEach-Object { "$_" })
            $rel = @($names | Where-Object { Covers $_ })
            if ($bound[$_.Thumbprint] -or $rel.Count) {
                $n = if ($nohost[$_.Thumbprint]) { $names | Select-Object -First 6 } elseif (-not $rel.Count) { $names | Select-Object -First 1 }
                     elseif ($bound[$_.Thumbprint]) { $rel | Select-Object -First 40 } else { $rel | Select-Object -First 3 }
                [ordered]@{ t = $_.Thumbprint; st = $st; n = @($n); i = (Short (CN $_.Issuer) 40); e = (Utc $_.NotAfter) }
            }
        }
    }
    $o.c = @($all | Sort-Object @{ e = { [int][bool]$bound[$_.t] } }, @{ e = { $_.e } } -Descending | Select-Object -First 12)
} catch { Gap 'cert store' $_ }

try {
    $pat = 'wacs|win-acme|acme|certbot|certify|letsencrypt|posh-acme|renew'
    $o.tk = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.TaskName -notlike 'WindowsAdminCenter*' -and
            ($_.TaskName -match $pat -or (@($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ') -match $pat) } |
        Select-Object -First 6 | ForEach-Object {
            $i = $_ | Get-ScheduledTaskInfo
            [ordered]@{ n = (Short $_.TaskName 50); s = "$($_.State)"; lr = (Utc $i.LastRunTime); r = $i.LastTaskResult
                        nr = (Utc $i.NextRunTime); x = (Short (Split-Path -Leaf "$(@($_.Actions)[0].Execute)") 30) }
        })
} catch { Gap 'scheduled tasks' $_ }

try {
    $o.sv = @(Get-Service -Name '*certify*', '*acme*' -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)=$($_.Status)" })
} catch { Gap 'renewal services' $_ }

$o.gaps = @($gaps)
$o | ConvertTo-Json -Depth 4 -Compress
