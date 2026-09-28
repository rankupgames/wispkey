param(
    [ValidateRange(1, 10)][int]$Runs = 3,
    [ValidateRange(1, 32)][int]$TestThreads = 14,
    [ValidateRange(30, 300)][int]$TimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This contention check requires Windows.' }

# Compile before constraining CPU: the experiment measures IPC, not rustc.
$artifacts = & cargo test --locked --test owner_ipc --no-run --message-format=json
if ($LASTEXITCODE -ne 0) { throw 'Failed to build owner IPC tests.' }
$testExecutables = @($artifacts | ForEach-Object {
    $artifact = $_ | ConvertFrom-Json
    if ($artifact.reason -eq 'compiler-artifact' -and $artifact.target.name -eq 'owner_ipc' -and $artifact.executable) {
        $artifact.executable
    }
})
if ($testExecutables.Count -ne 1) { throw 'Expected exactly one owner IPC test executable.' }

$currentProcess = [Diagnostics.Process]::GetCurrentProcess()
$originalAffinity = $currentProcess.ProcessorAffinity
$mask = $originalAffinity.ToInt64()
$singleCpu = $mask -band (-$mask)
if ($singleCpu -le 0) { throw 'No usable processor affinity bit.' }
$rows = @('| Run | CPU count | Test threads | Elapsed seconds | Exit |', '| --- | --- | --- | --- | --- |')
try {
    # Windows children inherit the parent affinity; set it before launching
    # the harness so its vault-initialization/server children are constrained.
    $currentProcess.ProcessorAffinity = [IntPtr]$singleCpu
    for ($iteration = 1; $iteration -le $Runs; $iteration++) {
        $stdoutPath = [IO.Path]::GetTempFileName()
        $stderrPath = [IO.Path]::GetTempFileName()
        $childProcess = $null
        try {
            $timer = [Diagnostics.Stopwatch]::StartNew()
            $childProcess = Start-Process -FilePath $testExecutables[0] `
                -ArgumentList "--test-threads=$TestThreads", '--nocapture' `
                -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
            # Keep a process handle open so Windows PowerShell 5.1 can retrieve
            # the exit code after a fast child has already terminated.
            $null = $childProcess.Handle
            if (-not $childProcess.WaitForExit($TimeoutSeconds * 1000)) {
                # Kill only this test process tree, including its disposable servers.
                & taskkill.exe /PID $childProcess.Id /T /F | Out-Null
                throw "Owner IPC contention run $iteration exceeded ${TimeoutSeconds}s."
            }
            $childProcess.WaitForExit()
            $timer.Stop()
            Get-Content -LiteralPath $stdoutPath
            Get-Content -LiteralPath $stderrPath
            $seconds = [Math]::Round($timer.Elapsed.TotalSeconds, 2)
            $rows += "| $iteration | 1 | $TestThreads | $seconds | $($childProcess.ExitCode) |"
            Write-Host "Owner IPC contention run ${iteration}: ${seconds}s, exit $($childProcess.ExitCode)"
            if ($childProcess.ExitCode -ne 0) { throw 'Owner IPC contention failed; subsequent runs are not retries.' }
        } finally {
            if ($childProcess) { $childProcess.Dispose() }
            Remove-Item -LiteralPath $stdoutPath, $stderrPath -ErrorAction SilentlyContinue
        }
    }
} finally {
    $currentProcess.ProcessorAffinity = $originalAffinity
    $currentProcess.Dispose()
    if ($env:GITHUB_STEP_SUMMARY) {
        @('## Windows owner IPC contention', '') + $rows | Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Encoding utf8
    }
}
