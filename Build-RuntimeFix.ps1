param(
    [string]$TccRoot = "$PSScriptRoot\..\toolchain\tcc",
    [string]$OutputPath = "$PSScriptRoot\..\dist\RideAnywhereSpecialAreaFix.dll"
)

$ErrorActionPreference = 'Stop'
$compiler = Join-Path $TccRoot 'tcc.exe'
$source = Join-Path $PSScriptRoot '..\src\RideAnywhereSpecialAreaFix.c'
if (-not (Test-Path -LiteralPath $compiler)) {
    throw "TinyCC was not found at $compiler"
}
if (-not (Test-Path -LiteralPath $source)) {
    throw "Source file was not found at $source"
}

$outputDirectory = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
& $compiler -m64 -shared -Wall -Werror -o $OutputPath $source
if ($LASTEXITCODE -ne 0) {
    throw "TinyCC failed with exit code $LASTEXITCODE"
}

$definitionPath = [IO.Path]::ChangeExtension($OutputPath, '.def')
if (Test-Path -LiteralPath $definitionPath) {
    Remove-Item -LiteralPath $definitionPath -Force
}

$bytes = [IO.File]::ReadAllBytes($OutputPath)
if ($bytes.Length -lt 0x40 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
    throw 'The output is not a valid PE image.'
}
$peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
$machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
if ($machine -ne 0x8664) {
    throw ('Expected an x64 DLL, found machine type 0x{0:X4}.' -f $machine)
}

Get-Item -LiteralPath $OutputPath | Select-Object FullName,Length
Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256
