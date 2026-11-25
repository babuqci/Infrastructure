/*
  Create (or replace) the SQL Agent job "QCI - Backup <db>".

  Daily full backup of ONE database to K:\MSSQL\Backup\<db>\, then delete that
  folder's .bak files older than 7 days. The delete step runs only after a
  successful, verified backup, so at least one recent backup always remains.
  If the backup fails, nothing is deleted.

  Set @db before running: 'qcidb' on most servers, 'qcidb-develop' on the
  development SQL server. Safe to re-run: it drops and recreates the job.
*/
SET NOCOUNT ON;
DECLARE @db       sysname       = N'qcidb';
-- Own subfolder per database, so cleanup never touches other backups in K:\MSSQL\Backup
DECLARE @dir      nvarchar(260) = N'K:\MSSQL\Backup\' + @db + N'\';
DECLARE @keepDays int           = 7;
DECLARE @runAt    int           = 10000;  -- HHMMSS, 01:00 server time
DECLARE @job      sysname       = N'QCI - Backup ' + @db;

IF DB_ID(@db) IS NULL
BEGIN
    RAISERROR(N'Database %s not found on this server; job not created.', 16, 1, @db);
    RETURN;
END;

EXEC master.sys.xp_create_subdir @dir;

DECLARE @backupCmd nvarchar(max) = N'
DECLARE @file nvarchar(400) = N''' + @dir + @db + N'_'' + FORMAT(SYSDATETIME(), ''yyyyMMdd_HHmmss'') + N''.bak'';
BACKUP DATABASE ' + QUOTENAME(@db) + N' TO DISK = @file WITH COMPRESSION, CHECKSUM, INIT, STATS = 10;
RESTORE VERIFYONLY FROM DISK = @file WITH CHECKSUM;';

DECLARE @cleanupCmd nvarchar(max) = N'
DECLARE @cutoff datetime = DATEADD(day, -' + CAST(@keepDays AS nvarchar(5)) + N', GETDATE());
EXEC master.sys.xp_delete_file 0, N''' + @dir + N''', N''bak'', @cutoff, 0;';

IF EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = @job)
    EXEC msdb.dbo.sp_delete_job @job_name = @job;

DECLARE @owner sysname = SUSER_SNAME(0x01);  -- sa (works even if the sa login is disabled)
EXEC msdb.dbo.sp_add_job @job_name = @job, @owner_login_name = @owner,
     @description = N'Daily full backup to K:, keep 7 days. Managed by QCI Infrastructure repo (sql/).';

EXEC msdb.dbo.sp_add_jobstep @job_name = @job, @step_id = 1, @step_name = N'Backup and verify',
     @subsystem = N'TSQL', @database_name = N'master', @command = @backupCmd,
     @on_success_action = 3,  -- go to next step (cleanup)
     @on_fail_action = 2;     -- quit reporting failure: cleanup never runs

EXEC msdb.dbo.sp_add_jobstep @job_name = @job, @step_id = 2, @step_name = N'Delete backups older than 7 days',
     @subsystem = N'TSQL', @database_name = N'master', @command = @cleanupCmd,
     @on_success_action = 1, @on_fail_action = 2;

EXEC msdb.dbo.sp_add_jobschedule @job_name = @job, @name = N'Daily 01:00',
     @freq_type = 4, @freq_interval = 1, @active_start_time = @runAt;

EXEC msdb.dbo.sp_add_jobserver @job_name = @job, @server_name = N'(local)';

PRINT N'Created job "' + @job + N'" -> ' + @dir;
