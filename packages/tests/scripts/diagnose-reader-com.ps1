<#
.SYNOPSIS
    TEMPORARY v2 diagnostic: embedding-server and dialog evidence. DO NOT MERGE.

.DESCRIPTION
    Never fails: every probe reports its outcome. P1 pre-launches Reader
    as an embedding server and then connects COM to it. P2 enumerates the
    Reader process windows during a plain launch (a first-run/EULA dialog
    would appear here). P3 reports the registered LocalServer32 command.
    All processes this script starts are closed by it.
#>
$ErrorActionPreference = "Continue"

function Section {
    param([string]$Name)
    ""
    "=== $Name ==="
}

function Get-OwnedReaderExe {
    foreach ($key in @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Acrobat.exe",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\Acrobat.exe"
    )) {
        try {
            $exe = (Get-ItemProperty -LiteralPath $key -Name "(default)" -ErrorAction Stop)."(default)"
            if (-not [string]::IsNullOrWhiteSpace($exe) -and (Test-Path -LiteralPath $exe -PathType Leaf)) {
                return $exe
            }
        } catch {
        }
    }
    return $null
}

function Stop-OwnedProcess {
    param($Process)
    try {
        $Process.CloseMainWindow() | Out-Null
    } catch {
    }
    try {
        $Process.WaitForExit(10000) | Out-Null
    } catch {
    }
    try {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force
        }
    } catch {
    }
}

Section "p0-exe"
$exe = Get-OwnedReaderExe
"exe=$exe"

Section "p1-embedding-server"
if ($null -eq $exe) {
    "P1 SKIPPED (no exe)"
} else {
    try {
        $server = Start-Process -FilePath $exe -ArgumentList "-Embedding" -PassThru
        Start-Sleep -Seconds 20
        $server.Refresh()
        "P1 server alive=$(-not $server.HasExited) responding=$($server.Responding) title=$($server.MainWindowTitle)"
        try {
            $app = New-Object -ComObject AcroExch.App
            "P1 COM-CONNECT ok"
            try {
                $app.Exit()
            } catch {
            }
            try {
                [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($app)
            } catch {
            }
        } catch {
            "P1 COM-CONNECT failed: $($_.Exception.Message)"
        }
        Stop-OwnedProcess -Process $server
    } catch {
        "P1 PROBE-ERROR $($_.Exception.Message)"
    }
}

Section "p2-dialogs"
if ($null -eq $exe) {
    "P2 SKIPPED (no exe)"
} else {
    try {
        Add-Type -AssemblyName UIAutomationClient
        $plain = Start-Process -FilePath $exe -PassThru
        Start-Sleep -Seconds 15
        $plain.Refresh()
        "P2 alive=$(-not $plain.HasExited) responding=$($plain.Responding) mainTitle=$($plain.MainWindowTitle)"
        try {
            $root = [System.Windows.Automation.AutomationElement]::RootElement
            $windows = $root.FindAll(
                [System.Windows.Automation.TreeScope]::Children,
                [System.Windows.Automation.Condition]::TrueCondition
            )
            foreach ($window in $windows) {
                try {
                    if ($window.Current.ProcessId -eq $plain.Id) {
                        "P2 window title=$($window.Current.Name) class=$($window.Current.ClassName)"
                    }
                } catch {
                }
            }
        } catch {
            "P2 UIA-PROBE-ERROR $($_.Exception.Message)"
        }
        Stop-OwnedProcess -Process $plain
    } catch {
        "P2 PROBE-ERROR $($_.Exception.Message)"
    }
}

Section "p3-localserver-cmdline"
try {
    $clsid = (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Classes\AcroExch.App\CLSID" `
        -Name "(default)" -ErrorAction Stop)."(default)"
    $command = (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Classes\CLSID\$clsid\LocalServer32" `
        -Name "(default)" -ErrorAction Stop)."(default)"
    "P3 clsid=$clsid"
    "P3 localserver=$command"
} catch {
    "P3 PROBE-ERROR $($_.Exception.Message)"
}

""
"=== v2 diagnostic complete (always exits 0) ==="
exit 0
