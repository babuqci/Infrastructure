# Read-only SQL Server discovery, run on a VM through Azure Run Command.
# Prints one JSON object: K: drive, SQL services, databases, last qcidb backup,
# Agent jobs, and whether this identity can create jobs. Changes nothing.
$ErrorActionPreference = 'Continue'
$out = [ordered]@{ host = $env:COMPUTERNAME }

$k = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='K:'" -ErrorAction SilentlyContinue
$out.kDrive = if ($k) { @{ sizeGB = [math]::Round($k.Size / 1GB); freeGB = [math]::Round($k.FreeSpace / 1GB) } } else { $null }
$out.kBackupDir = if (Test-Path 'K:\MSSQL\Backup') {
    @(Get-ChildItem 'K:\MSSQL\Backup' -Recurse -Filter *.bak -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending | Select-Object -First 5 |
      ForEach-Object { @{ file = $_.FullName; mb = [math]::Round($_.Length / 1MB); written = $_.LastWriteTime.ToString('s') } })
} else { 'missing' }

$out.services = @(Get-Service -Name 'MSSQL*', 'SQLAgent*', 'SQLSERVERAGENT' -ErrorAction SilentlyContinue |
    ForEach-Object { @{ name = $_.Name; status = "$($_.Status)"; startType = "$($_.StartType)" } })

function Query($sql) {
    $c = New-Object System.Data.SqlClient.SqlConnection 'Server=.;Integrated Security=SSPI;Connect Timeout=10'
    $c.Open()
    try {
        $cmd = $c.CreateCommand(); $cmd.CommandText = $sql; $cmd.CommandTimeout = 30
        $t = New-Object System.Data.DataTable; $t.Load($cmd.ExecuteReader())
        @($t.Rows | ForEach-Object { $r = $_; $h = [ordered]@{}; foreach ($col in $t.Columns) { $h[$col.ColumnName] = "$($r[$col])" }; $h })
    } finally { $c.Close() }
}

try {
    $out.sql = (Query "SELECT SERVERPROPERTY('Edition') AS edition, SERVERPROPERTY('ProductVersion') AS version,
        SERVERPROPERTY('ProductUpdateLevel') AS cu, SUSER_SNAME() AS login, IS_SRVROLEMEMBER('sysadmin') AS sysadmin,
        (SELECT CAST(value_in_use AS int) FROM sys.configurations WHERE name = 'max server memory (MB)') AS maxMemMB")[0]
    $out.databases = Query "SELECT d.name, d.recovery_model_desc AS recovery, d.state_desc AS state,
        CAST(SUM(f.size) * 8 / 1024 AS int) AS sizeMB
        FROM sys.databases d JOIN sys.master_files f ON f.database_id = d.database_id
        WHERE d.database_id > 4 GROUP BY d.name, d.recovery_model_desc, d.state_desc"
    $out.lastBackups = Query "SELECT database_name AS db, type, MAX(backup_finish_date) AS lastFinish,
        MAX(physical_device_name) AS lastFile
        FROM msdb.dbo.backupset b JOIN msdb.dbo.backupmediafamily m ON m.media_set_id = b.media_set_id
        WHERE database_name IN ('qcidb', 'qcidb-develop') GROUP BY database_name, type"
    $out.jobs = Query "SELECT j.name, j.enabled, h.run_status AS lastStatus, h.run_date AS lastRunDate
        FROM msdb.dbo.sysjobs j OUTER APPLY (SELECT TOP 1 run_status, run_date FROM msdb.dbo.sysjobhistory
        WHERE job_id = j.job_id AND step_id = 0 ORDER BY instance_id DESC) h"
} catch {
    $out.sqlError = $_.Exception.Message
}

$out | ConvertTo-Json -Depth 5 -Compress
