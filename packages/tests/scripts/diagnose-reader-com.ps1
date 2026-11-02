<#
.SYNOPSIS
    TEMPORARY CI diagnostic for Acrobat COM activation failures. DO NOT MERGE.

.DESCRIPTION
    Dumps identity, registration, install, and reboot-pending state, then
    probes AcroExch.App activation from 64-bit, 32-bit, and unelevated
    contexts. Never fails: every probe reports ok/failed/inconclusive.
    Finally applies the classic DCOM identity mitigation (AppID RunAs to
    Interactive User) so the later oracle step tests exactly one variable.
#>
$ErrorActionPreference = "Continue"

function Section {
    param([string]$Name)
    ""
    "=== $Name ==="
}

function Show-Command {
    param([string]$Label, [scriptblock]$Body)
    try {
        $output = & $Body 2>&1 | Out-String
        "$Label`: $($output.Trim())"
    } catch {
        "$Label`: PROBE-ERROR $($_.Exception.Message)"
    }
}

Section "identity"
Show-Command "whoami" { whoami }
Show-Command "mandatory-label" { whoami /groups | Select-String "Mandatory Label" }
Show-Command "admin-role" {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
Show-Command "session" { [System.Diagnostics.Process]::GetCurrentProcess().SessionId }

Section "com-registration"
Show-Command "progid-64" {
    (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Classes\AcroExch.App\CLSID" `
        -Name "(default)" -ErrorAction Stop)."(default)"
}
Show-Command "progid-user" {
    (Get-ItemProperty -LiteralPath "HKCU:\SOFTWARE\Classes\AcroExch.App\CLSID" `
        -Name "(default)" -ErrorAction Stop)."(default)"
}

$clsid = $null
try {
    $clsid = (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Classes\AcroExch.App\CLSID" `
        -Name "(default)" -ErrorAction Stop)."(default)"
} catch {
}
"clsid=$clsid"
if (-not [string]::IsNullOrWhiteSpace($clsid)) {
    Show-Command "localserver32" {
        (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Classes\CLSID\$clsid\LocalServer32" `
            -Name "(default)" -ErrorAction Stop)."(default)"
    }
    Show-Command "appid" {
        (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Classes\CLSID\$clsid" `
            -Name "AppID" -ErrorAction Stop).AppID
    }
}

Section "install-state"
Show-Command "winget-list" { winget list --id Adobe.Acrobat.Reader.64-bit --accept-source-agreements }
Show-Command "uninstall-entries" {
    Get-ChildItem -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" `
        -ErrorAction Stop | ForEach-Object {
        $display = (Get-ItemProperty -LiteralPath $_.PSPath -Name "DisplayName" `
            -ErrorAction SilentlyContinue).DisplayName
        if ($null -ne $display -and $display -like "Adobe*") { $display }
    }
}

Section "reboot-pending"
Show-Command "cbs-reboot-pending" {
    Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
}
Show-Command "wu-reboot-required" {
    Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
}
Show-Command "pending-rename" {
    $names = (Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($null -eq $names) { "none" } else { "$($names.Count) entries" }
}

Section "warmup-window"
$warmupExe = $null
foreach ($candidate in @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Acrobat.exe",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\Acrobat.exe"
)) {
    try {
        $path = (Get-ItemProperty -LiteralPath $candidate -Name "(default)" -ErrorAction Stop)."(default)"
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $warmupExe = $path
        }
    } catch {
    }
}
"warmup exe=$warmupExe"
if ($null -ne $warmupExe) {
    try {
        $warmup = Start-Process -FilePath $warmupExe -PassThru
        Start-Sleep -Seconds 20
        $warmup.Refresh()
        "warmup exited=$($warmup.HasExited) responding=$($warmup.Responding) title=$($warmup.MainWindowTitle)"
        try {
            $warmup.CloseMainWindow() | Out-Null
        } catch {
        }
    } catch {
        "warmup PROBE-ERROR $($_.Exception.Message)"
    }
}

Section "com-probe-64bit"
try {
    $probe = New-Object -ComObject AcroExch.App
    "COM-64BIT ok"
    try {
        $probe.Exit()
    } catch {
    }
    try {
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($probe)
    } catch {
    }
} catch {
    "COM-64BIT failed: $($_.Exception.Message)"
}

Section "com-probe-32bit"
try {
    $probe32 = Join-Path ([System.IO.Path]::GetTempPath()) "acrobat-com-probe32.ps1"
    '$probe = New-Object -ComObject AcroExch.App; "COM-32BIT ok"; $probe.Exit()' | `
        Out-File -LiteralPath $probe32 -Encoding ascii -Force
    $syswow = Join-Path $env:SystemRoot "SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    $output32 = & $syswow -NoLogo -NoProfile -NonInteractive -File $probe32 2>&1 | Out-String
    "COM-32BIT result: $($output32.Trim())"
} catch {
    "COM-32BIT PROBE-ERROR $($_.Exception.Message)"
}

Section "com-probe-unelevated"
try {
    $unelevated = & runas /trustlevel:0x20000 "powershell.exe -NoLogo -NoProfile -NonInteractive -Command `"& { `$p = New-Object -ComObject AcroExch.App; 'COM-UNELEVATED ok'; `$p.Exit() }`"" 2>&1 | Out-String
    "COM-UNELEVATED result: $($unelevated.Trim())"
} catch {
    "COM-UNELEVATED PROBE-ERROR $($_.Exception.Message)"
}

Section "dcom-identity-mitigation"
try {
    if ([string]::IsNullOrWhiteSpace($clsid)) {
        "mitigation SKIPPED (no CLSID)"
    } else {
        $appId = (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Classes\CLSID\$clsid" `
            -Name "AppID" -ErrorAction Stop).AppID
        $appIdKey = "HKLM:\SOFTWARE\Classes\AppID\$appId"
        if (-not (Test-Path -LiteralPath $appIdKey)) {
            New-Item -Path $appIdKey -Force | Out-Null
        }
        New-ItemProperty -LiteralPath $appIdKey -Name "RunAs" -Value "Interactive User" `
            -PropertyType String -Force | Out-Null
        $readback = (Get-ItemProperty -LiteralPath $appIdKey -Name "RunAs").RunAs
        "mitigation AppID=$appId RunAs=$readback"
    }
} catch {
    "mitigation PROBE-ERROR $($_.Exception.Message)"
}

""
"=== diagnostic complete (always exits 0) ==="
exit 0
