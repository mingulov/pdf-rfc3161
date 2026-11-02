<#
.SYNOPSIS
    TEMPORARY v3 diagnostic: integrity-level split evidence. DO NOT MERGE.

.DESCRIPTION
    Reports the integrity level of this process and of a warm-launched
    Reader process, plus the default PDF handler. A High/Medium split
    between the COM client and the Reader server explains E_FAIL.
#>
$ErrorActionPreference = "Continue"

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class IntegrityQuery {
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr buffer, int length, out int needed);
    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);
    public static string LevelOf(int pid) {
        var process = System.Diagnostics.Process.GetProcessById(pid);
        IntPtr token;
        if (!OpenProcessToken(process.Handle, 8u, out token)) return "query-failed";
        try {
            int needed;
            GetTokenInformation(token, 25, IntPtr.Zero, 0, out needed);
            IntPtr buffer = Marshal.AllocHGlobal(needed);
            try {
                if (!GetTokenInformation(token, 25, buffer, needed, out needed)) return "query-failed";
                IntPtr sid = Marshal.ReadIntPtr(buffer);
                byte count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                uint rid = (uint)Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1)));
                return "0x" + rid.ToString("X");
            } finally {
                Marshal.FreeHGlobal(buffer);
            }
        } finally {
            CloseHandle(token);
        }
    }
}
"@

"self pid=$PID IL=$([IntegrityQuery]::LevelOf($PID))"

$exe = $null
try {
    $exe = (Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Acrobat.exe" `
        -Name "(default)" -ErrorAction Stop)."(default)"
} catch {
}
"reader exe=$exe"

if ($null -ne $exe) {
    try {
        $reader = Start-Process -FilePath $exe -PassThru
        Start-Sleep -Seconds 15
        $reader.Refresh()
        if ($reader.HasExited) {
            "reader exited during warmup"
        } else {
            "reader pid=$($reader.Id) IL=$([IntegrityQuery]::LevelOf($reader.Id)) title=$($reader.MainWindowTitle)"
        }
        try {
            $reader.CloseMainWindow() | Out-Null
        } catch {
        }
        try {
            $reader.WaitForExit(10000) | Out-Null
        } catch {
        }
        try {
            $reader.Refresh()
            if (-not $reader.HasExited) {
                Stop-Process -Id $reader.Id -Force
            }
        } catch {
        }
    } catch {
        "reader PROBE-ERROR $($_.Exception.Message)"
    }
}

try {
    $choice = (Get-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice" `
        -Name "ProgId" -ErrorAction Stop).ProgId
    "default pdf handler=$choice"
} catch {
    "default pdf handler=unknown"
}

"=== v3 diagnostic complete (always exits 0) ==="
exit 0
