# Read-only SQL Server health probe, run on each SQL VM through Azure Run Command by
# `qci-infra sql-check`. Reads Windows services, fixed disks, sys.databases and msdb
# backup history; creates, changes and deletes nothing. Each read is independent:
# a failure (e.g. a permission the SYSTEM login lacks) is reported in `gaps`, and the
# rest still comes back. Output is ONE compact JSON line: Run Command keeps only ~4 KB.
$ErrorActionPreference = 'Stop'
$o = [ordered]@{ host = $env:COMPUTERNAME }
$gaps = New-Object System.Collections.ArrayList

function Short([string]$s, [int]$n) { if ($s.Length -gt $n) { $s.Substring(0, $n) } else { $s } }
function Gap($what, $err) { [void]$gaps.Add("${what}: " + (Short ($err.Exception.Message -replace '\s+', ' ') 150)) }

function Q($sql, $db = '') {
    $c = New-Object System.Data.SqlClient.SqlConnection 'Server=.;Integrated Security=SSPI;Connect Timeout=15'
    $c.Open()
    try {
        $cmd = $c.CreateCommand(); $cmd.CommandText = $sql; $cmd.CommandTimeout = 60
        [void]$cmd.Parameters.AddWithValue('@db', $db)
        $t = New-Object System.Data.DataTable; $t.Load($cmd.ExecuteReader())
        @($t.Rows | ForEach-Object { $r = $_; $h = [ordered]@{}; foreach ($col in $t.Columns) { $h[$col.ColumnName] = "$($r[$col])" }; $h })
    } finally { $c.Dispose() }
}

try {
    $svc = [ordered]@{}
    foreach ($n in 'MSSQLSERVER', 'SQLSERVERAGENT') {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        $svc[$n] = if ($s) { "$($s.Status)" } else { 'Missing' }
    }
    $o.svc = $svc
} catch { Gap 'services' $_ }

try {
    $o.drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        [ordered]@{ d = $_.DeviceID.TrimEnd(':'); size = [math]::Round($_.Size / 1GB, 1); free = [math]::Round($_.FreeSpace / 1GB, 1) } })
} catch { Gap 'disks' $_ }

try {
    $p = @(Q "SELECT CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) AS edition,
        CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) AS version, IS_SRVROLEMEMBER('sysadmin') AS sysadmin")[0]
    $o.edition = $p.edition; $o.version = $p.version; $o.sysadmin = $p.sysadmin
} catch { Gap 'serverproperty' $_ }

try {
    $dbs = @(Q "SELECT name, state_desc AS state FROM sys.databases WHERE LOWER(name) IN ('qcidb', 'qcidb-develop')")
    $o.dbs = @($dbs | ForEach-Object { "$($_.name)=$($_.state)" })
    $pick = @($dbs | Where-Object { $_.name -eq 'qcidb' }) + @($dbs) | Select-Object -First 1
    $o.db = if ($pick) { $pick.name } else { $null }
} catch { Gap 'sys.databases' $_ }

if ($o.db) {
    try {
        # Latest backup of each type with the file of THAT backup; finish time converted to UTC
        # (backupset.time_zone is in 15-minute units, 127 = unknown: fall back to the server's offset).
        $bk = [ordered]@{}
        foreach ($r in @(Q "SELECT type, CONVERT(varchar(19), DATEADD(minute, CASE WHEN time_zone = 127
              THEN DATEDIFF(minute, GETDATE(), GETUTCDATE()) ELSE -15 * time_zone END, backup_finish_date), 126) AS t, f
            FROM (SELECT b.type, b.time_zone, b.backup_finish_date, m.physical_device_name AS f,
                    ROW_NUMBER() OVER (PARTITION BY b.type ORDER BY b.backup_finish_date DESC) AS rn
                  FROM msdb.dbo.backupset b JOIN msdb.dbo.backupmediafamily m ON m.media_set_id = b.media_set_id
                  WHERE b.database_name = @db AND b.type IN ('D', 'I', 'L')) x
            WHERE rn = 1" $o.db)) {
            $bk[$r.type] = [ordered]@{ t = "$($r.t)Z"; f = (Short $r.f 200) }
        }
        $o.bk = $bk
    } catch { Gap 'msdb.backupset' $_ }
}

$o.gaps = @($gaps)
$o | ConvertTo-Json -Depth 4 -Compress
