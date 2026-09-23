param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Chrome', 'Edge', 'Firefox')]
    [string]$Browser,
    [string]$ExtensionId,
    [string]$HostPath = (Join-Path $PSScriptRoot '..\target\release\wispkey-browser-host.exe')
)
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') { throw 'Browser handoff currently requires Windows Hello.' }
$hostBinary = (Get-Item -LiteralPath $HostPath).FullName
if (-not (Test-Path -LiteralPath $hostBinary -PathType Leaf)) { throw 'Build the native host first.' }
$nativeName = 'com.wispkey.browser'
$manifestDirectory = Join-Path $env:LOCALAPPDATA 'WispKey\BrowserHost'
$null = New-Item -ItemType Directory -Path $manifestDirectory -Force
$manifestPath = Join-Path $manifestDirectory "$($Browser.ToLowerInvariant()).json"
$manifest = [ordered]@{
    name = $nativeName
    description = 'WispKey local browser approval host'
    path = $hostBinary
    type = 'stdio'
}
switch ($Browser) {
    'Firefox' {
        if ($ExtensionId -and $ExtensionId -ne 'browser-handoff@wispkey.local') {
            throw 'Use the Firefox extension ID from the WispKey manifest.'
        }
        $manifest.allowed_extensions = @('browser-handoff@wispkey.local')
        $registryPath = "HKCU:\Software\Mozilla\NativeMessagingHosts\$nativeName"
    }
    'Chrome' {
        if ($ExtensionId -cnotmatch '^[a-p]{32}$') { throw 'Supply the extension ID from chrome://extensions.' }
        $manifest.allowed_origins = @("chrome-extension://$ExtensionId/")
        $registryPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$nativeName"
    }
    'Edge' {
        if ($ExtensionId -cnotmatch '^[a-p]{32}$') { throw 'Supply the extension ID from edge://extensions.' }
        $manifest.allowed_origins = @("chrome-extension://$ExtensionId/")
        $registryPath = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$nativeName"
    }
}
$json = $manifest | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText($manifestPath, $json, [System.Text.UTF8Encoding]::new($false))
$null = New-Item -Path $registryPath -Force
Set-Item -LiteralPath $registryPath -Value $manifestPath
Write-Output "Registered WispKey for $Browser. Install the extension only in your human-controlled profile."
