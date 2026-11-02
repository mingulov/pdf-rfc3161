<#
.SYNOPSIS
    Opens fixture PDFs in Adobe Acrobat Reader and reports signature state.

.DESCRIPTION
    Drives Reader through COM automation (AcroExch.App / AVDoc / PDDoc) and
    reads each signature field through the Acrobat JavaScript bridge
    (Field.signatureValidate / Field.signatureInfo). Prints one JSON report
    to stdout for the vitest wrapper (test/unit/acrobat-reader.test.ts),
    which owns every pass/fail assertion.

    Verdicts are data: an invalid or unsigned PDF still exits 0. A nonzero
    exit means the harness itself failed (bad manifest, missing Reader,
    a document that would not open, an unreadable signature field).

    Report contract version 1:
        {
            "oracle": "acrobat-reader-oracle",
            "version": 1,
            "reader": { "product": "Acrobat Reader", "version": "24.x..." | null },
            "results": [
                {
                    "name": "<case>",
                    "fields": [
                        {
                            "name": "<field>",
                            "fieldType": "signature",
                            "validate": -1|0|1|2|3|4,
                            "status": <number|null>,
                            "docValidity": <number|null>,
                            "date": <string|null>,
                            "signer": <string|null>
                        }
                    ] | null
                }
            ]
        }

    A null fields array is the version-independent encoding of an empty
    field list (ConvertTo-Json collapses empty arrays). Only signature
    fields are reported; other field types are skipped.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath
)

$ErrorActionPreference = "Stop"

function Read-ManifestCases {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Manifest does not exist: $Path"
    }
    $manifest = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($null -eq $manifest.cases -or $manifest.cases.Count -eq 0) {
        throw "Manifest defines zero cases: $Path"
    }
    foreach ($case in $manifest.cases) {
        if ([string]::IsNullOrWhiteSpace($case.name)) {
            throw "Manifest case without a name: $Path"
        }
        if ([string]::IsNullOrWhiteSpace($case.pdf)) {
            throw "Manifest case $($case.name) has no pdf path"
        }
        if (-not (Test-Path -LiteralPath $case.pdf -PathType Leaf)) {
            throw "Manifest case $($case.name) pdf does not exist: $($case.pdf)"
        }
    }
    return $manifest.cases
}

function Get-ReaderExePath {
    # Probe every registration the Adobe installer is known to use
    # (64-bit, 32-bit-redirected, per-user; AcroRd32.exe before and
    # Acrobat.exe since the Reader 26 unification).
    $exeNames = @("AcroRd32.exe", "Acrobat.exe")
    $appPathRoots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
    )
    foreach ($root in $appPathRoots) {
        foreach ($exeName in $exeNames) {
            $key = Join-Path $root $exeName
            try {
                $exePath = (Get-ItemProperty -LiteralPath $key -Name "(default)" `
                    -ErrorAction Stop)."(default)"
                if (-not [string]::IsNullOrWhiteSpace($exePath) -and `
                    (Test-Path -LiteralPath $exePath -PathType Leaf)) {
                    return $exePath
                }
            } catch {
            }
        }
    }
    return $null
}

function Get-ReaderVersion {
    param([string]$ExePath)
    if ([string]::IsNullOrWhiteSpace($ExePath)) {
        return $null
    }
    try {
        return (Get-Item -LiteralPath $ExePath).VersionInfo.ProductVersion
    } catch {
        return $null
    }
}

function Start-ReaderWarmup {
    param([string]$ExePath)
    # A fresh Reader install often refuses its first COM activation until
    # the executable has launched once. Launch it, let first-run
    # initialization settle, then ask it to close (best effort: a lingering
    # window on an ephemeral runner is harmless).
    try {
        $process = Start-Process -FilePath $ExePath -PassThru
        Start-Sleep -Seconds 15
        try {
            $process.CloseMainWindow() | Out-Null
        } catch {
        }
        try {
            $process.WaitForExit(15000) | Out-Null
        } catch {
        }
    } catch {
    }
}

function Get-ComDiagnostics {
    $lines = @()
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $lines += "user=$($identity.Name) admin=$admin"
    } catch {
    }
    try {
        $session = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        $lines += "session=$session"
    } catch {
    }
    try {
        $registered = Test-Path -LiteralPath "HKCR:\AcroExch.App"
        $lines += "AcroExch.App registered=$registered"
    } catch {
    }
    try {
        $running = @(Get-Process -Name "Acrobat", "AcroRd32" -ErrorAction SilentlyContinue)
        $lines += "reader processes running=$($running.Count)"
    } catch {
    }
    return ($lines -join " ")
}

function New-ReaderComApp {
    param([string]$ExePath)
    $lastError = $null
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            return New-Object -ComObject AcroExch.App
        } catch {
            $lastError = $_
        }
        if ($attempt -lt 3) {
            if ([string]::IsNullOrWhiteSpace($ExePath)) {
                Start-Sleep -Seconds 10
            } else {
                Start-ReaderWarmup -ExePath $ExePath
            }
        }
    }
    $detail = "unknown error"
    if ($null -ne $lastError) {
        $detail = $lastError.Exception.Message
    }
    throw "Could not create AcroExch.App after 3 attempts: $detail [$(Get-ComDiagnostics)]"
}

function Read-JsScalar {
    param([scriptblock]$Reader)
    try {
        return (& $Reader)
    } catch {
        return $null
    }
}

function Read-JsText {
    param([scriptblock]$Reader)
    try {
        $value = & $Reader
        if ($null -eq $value) {
            return $null
        }
        return [string]$value
    } catch {
        return $null
    }
}

function Get-SignatureFields {
    param($JsObject, [string]$CaseName)
    $found = @()
    $fieldCount = $JsObject.numFields
    for ($index = 0; $index -lt $fieldCount; $index++) {
        $fieldName = $JsObject.getNthFieldName($index)
        $field = $JsObject.getField($fieldName)
        if ($field.type -ne "signature") {
            continue
        }
        try {
            $validate = [int]$field.signatureValidate()
        } catch {
            throw "Case $CaseName field $fieldName`: signatureValidate failed: $($_.Exception.Message)"
        }
        try {
            $info = $field.signatureInfo()
        } catch {
            throw "Case $CaseName field $fieldName`: signatureInfo failed: $($_.Exception.Message)"
        }
        $found += @{
            name = [string]$fieldName
            fieldType = "signature"
            validate = $validate
            status = (Read-JsScalar { $info.status })
            docValidity = (Read-JsScalar { $info.docValidity })
            date = (Read-JsText { $info.date })
            signer = (Read-JsText { $info.signer })
        }
    }
    return $found
}

function Use-ComObject {
    param($ComObject)
    if ($null -ne $ComObject) {
        try {
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($ComObject)
        } catch {
        }
    }
}

$cases = Read-ManifestCases -Path $ManifestPath
$readerExePath = Get-ReaderExePath
$readerVersion = Get-ReaderVersion -ExePath $readerExePath

$app = New-ReaderComApp -ExePath $readerExePath
try {
    try {
        $app.Hide()
    } catch {
    }
    $caseResults = @()
    foreach ($case in $cases) {
        $pdfPath = (Resolve-Path -LiteralPath $case.pdf).Path
        $avDoc = New-Object -ComObject AcroExch.AVDoc
        try {
            if (-not $avDoc.Open($pdfPath, "")) {
                throw "Case $($case.name): Reader could not open $pdfPath"
            }
            $pdDoc = $avDoc.GetPDDoc()
            try {
                $jso = $pdDoc.GetJSObject()
                if ($null -eq $jso) {
                    throw "Case $($case.name): Reader returned no JavaScript bridge"
                }
                try {
                    # Array-subexpression: a function returning zero or one
                    # field would otherwise arrive as $null or a scalar.
                    $signatureFields = @(Get-SignatureFields -JsObject $jso -CaseName $case.name)
                } finally {
                    Use-ComObject -ComObject $jso
                }
            } finally {
                Use-ComObject -ComObject $pdDoc
            }
        } finally {
            try {
                $avDoc.Close(1)
            } catch {
            }
            Use-ComObject -ComObject $avDoc
        }
        $fieldList = $null
        if ($signatureFields.Count -gt 0) {
            $fieldList = $signatureFields
        }
        $caseResults += @{
            name = [string]$case.name
            fields = $fieldList
        }
    }
} finally {
    try {
        $app.Exit()
    } catch {
    }
    Use-ComObject -ComObject $app
}

@{
    oracle = "acrobat-reader-oracle"
    version = 1
    reader = @{
        product = "Acrobat Reader"
        version = $readerVersion
    }
    results = $caseResults
} | ConvertTo-Json -Depth 8 -Compress
