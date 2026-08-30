param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DllPath,
    [ValidateSet('1.16.2', '1.17')]
    [string]$GameVersion = '1.17'
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $DllPath)) {
    throw "RideAnywhere DLL is missing: $DllPath"
}

function Find-ByteSequence([byte[]]$Bytes, [byte[]]$Needle) {
    $hits = [Collections.Generic.List[int]]::new()
    for ($i = 0; $i -le $Bytes.Length - $Needle.Length; $i++) {
        $match = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Bytes[$i + $j] -ne $Needle[$j]) { $match = $false; break }
        }
        if ($match) { $hits.Add($i) }
    }
    return $hits.ToArray()
}

function Replace-ByteSequence([byte[]]$Bytes, [byte[]]$Old, [byte[]]$New, [string]$Label) {
    $hits = Find-ByteSequence $Bytes $Old
    if ($hits.Count -ne 1) {
        throw "$Label expected exactly one occurrence, found $($hits.Count)."
    }
    if ($Old.Length -ne $New.Length) { throw "$Label replacement length differs." }
    [Array]::Copy($New, 0, $Bytes, $hits[0], $New.Length)
    return $hits[0]
}

$bytes = [IO.File]::ReadAllBytes($DllPath)
$oldSignatureText = '80 ? ? ? ? ? ? 48 ? ? ? ? 48 ? ? ? ? ? ? ? ? 40 ? ? ? ? ? 44 ? ? ? ? ? ? ? 48 ? ? ? ? ? ? ? ? E8 ? ? ? ? 48'
$oldSignature = [Text.Encoding]::ASCII.GetBytes($oldSignatureText)
# RideAnywhere's parser requires a wildcard-bearing AOB with enough fixed bytes
# to be a useful scan pattern. Version 1.16.2 still accepts the original
# signature; 1.17 needs the current 12-byte instruction prefix.
$signatureConfig = @{
    '1.16.2' = @{
        SignatureText = $oldSignatureText
        Prefix = '80 ? ? ? ? ? ? 48'
        Patch = 'C6 41 36 00 B0 00 90'
    }
    '1.17' = @{
        SignatureText = ((@('80', '78', '36', '00', '0F', '95', 'C0', '40', 'B7', '01', '88', '06') + @(1..38 | ForEach-Object { '?' })) -join ' ')
        Prefix = '80 78 36 00 0F 95 C0'
        Patch = 'C6 40 36 00 B0 00 90'
    }
}
$config = $signatureConfig[$GameVersion]
$otherGameVersion = if ($GameVersion -eq '1.16.2') { '1.17' } else { '1.16.2' }
$otherConfig = $signatureConfig[$otherGameVersion]
$signatureSlotLength = 112
$newSignatureText = $config.SignatureText
$newSignatureBytes = [Text.Encoding]::ASCII.GetBytes($newSignatureText)
if ($newSignatureBytes.Length -gt $signatureSlotLength) {
    throw "Updated AOB text exceeds the reserved string slot: $($newSignatureBytes.Length) > $signatureSlotLength."
}
$newSignature = [byte[]]::new($signatureSlotLength)
$newSignatureBytes.CopyTo($newSignature, 0)
$newPatch = [Text.Encoding]::ASCII.GetBytes($config.Patch)

$newSignaturePrefix = [Text.Encoding]::ASCII.GetBytes($newSignatureText)
$otherSignatureText = $otherConfig.SignatureText
$otherSignaturePrefix = [Text.Encoding]::ASCII.GetBytes($otherSignatureText)
$shortSignaturePrefix = [Text.Encoding]::ASCII.GetBytes($config.Prefix)
$otherShortSignaturePrefix = [Text.Encoding]::ASCII.GetBytes($otherConfig.Prefix)
$legacyShortSignatureTexts = @('80 78 36 00 0F 95 C0', '80 79 36 00 0F 95 C0')
$oldSignatureHits = Find-ByteSequence $bytes $oldSignature
$newSignatureHits = Find-ByteSequence $bytes $newSignaturePrefix
$otherSignatureHits = Find-ByteSequence $bytes $otherSignaturePrefix
$shortSignatureHits = Find-ByteSequence $bytes $shortSignaturePrefix
$otherShortSignatureHits = Find-ByteSequence $bytes $otherShortSignaturePrefix
$legacyShortSignatureHits = 0
foreach ($legacyText in $legacyShortSignatureTexts) {
    if ((Find-ByteSequence $bytes ([Text.Encoding]::ASCII.GetBytes($legacyText))).Count -eq 1) {
        $legacyShortSignatureHits++
    }
}
if ($oldSignatureHits.Count -eq 1) {
    [Array]::Clear($bytes, $oldSignatureHits[0], $signatureSlotLength)
    [Array]::Copy($newSignature, 0, $bytes, $oldSignatureHits[0], $newSignature.Length)
    $sigOffset = $oldSignatureHits[0]
} elseif ($oldSignatureHits.Count -eq 0 -and $newSignatureHits.Count -eq 1) {
    $sigOffset = $newSignatureHits[0]
} elseif ($oldSignatureHits.Count -eq 0 -and $newSignatureHits.Count -eq 0 -and $otherSignatureHits.Count -eq 1) {
    [Array]::Clear($bytes, $otherSignatureHits[0], $signatureSlotLength)
    [Array]::Copy($newSignature, 0, $bytes, $otherSignatureHits[0], $newSignature.Length)
    $sigOffset = $otherSignatureHits[0]
} elseif ($oldSignatureHits.Count -eq 0 -and $newSignatureHits.Count -eq 0 -and $otherSignatureHits.Count -eq 0 -and $shortSignatureHits.Count -eq 1) {
    [Array]::Clear($bytes, $shortSignatureHits[0], $signatureSlotLength)
    [Array]::Copy($newSignature, 0, $bytes, $shortSignatureHits[0], $newSignature.Length)
    $sigOffset = $shortSignatureHits[0]
} elseif ($oldSignatureHits.Count -eq 0 -and $newSignatureHits.Count -eq 0 -and $otherSignatureHits.Count -eq 0 -and $shortSignatureHits.Count -eq 0 -and $otherShortSignatureHits.Count -eq 0 -and $legacyShortSignatureHits -eq 1) {
    $legacyOffset = $null
    foreach ($legacyText in $legacyShortSignatureTexts) {
        $hits = Find-ByteSequence $bytes ([Text.Encoding]::ASCII.GetBytes($legacyText))
        if ($hits.Count -eq 1) { $legacyOffset = $hits[0]; break }
    }
    [Array]::Clear($bytes, $legacyOffset, $signatureSlotLength)
    [Array]::Copy($newSignature, 0, $bytes, $legacyOffset, $newSignature.Length)
    $sigOffset = $legacyOffset
} elseif ($oldSignatureHits.Count -eq 0 -and $newSignatureHits.Count -eq 0 -and $otherSignatureHits.Count -eq 0 -and $shortSignatureHits.Count -eq 0 -and $otherShortSignatureHits.Count -eq 1) {
    [Array]::Clear($bytes, $otherShortSignatureHits[0], $signatureSlotLength)
    [Array]::Copy($newSignature, 0, $bytes, $otherShortSignatureHits[0], $newSignature.Length)
    $sigOffset = $otherShortSignatureHits[0]
} elseif ($oldSignatureHits.Count -eq 0 -and $newSignatureHits.Count -eq 0 -and $otherSignatureHits.Count -eq 0 -and $shortSignatureHits.Count -eq 0 -and $otherShortSignatureHits.Count -eq 0 -and $legacyShortSignatureHits -ne 1) {
    throw "RideAnywhere AOB signature for game $GameVersion expected one old/current/alternate occurrence, found old=$($oldSignatureHits.Count), current=$($newSignatureHits.Count), alternate=$($otherSignatureHits.Count), short=$($shortSignatureHits.Count), alternateShort=$($otherShortSignatureHits.Count), legacyShort=$legacyShortSignatureHits."
} else {
    throw "RideAnywhere AOB signature for game $GameVersion expected one old/current/alternate occurrence, found old=$($oldSignatureHits.Count), current=$($newSignatureHits.Count), alternate=$($otherSignatureHits.Count), short=$($shortSignatureHits.Count), alternateShort=$($otherShortSignatureHits.Count), legacyShort=$legacyShortSignatureHits."
}

$newPatchHits = Find-ByteSequence $bytes $newPatch
$otherPatch = [Text.Encoding]::ASCII.GetBytes($otherConfig.Patch)
$otherPatchHits = Find-ByteSequence $bytes $otherPatch
if ($newPatchHits.Count -eq 1) {
    $patchOffset = $newPatchHits[0]
} elseif ($newPatchHits.Count -eq 0 -and $otherPatchHits.Count -eq 1) {
    [Array]::Copy($newPatch, 0, $bytes, $otherPatchHits[0], $newPatch.Length)
    $patchOffset = $otherPatchHits[0]
} else {
    throw "RideAnywhere patch bytes for game $GameVersion expected one current or alternate occurrence, found current=$($newPatchHits.Count), alternate=$($otherPatchHits.Count)."
}
[IO.File]::WriteAllBytes($DllPath, $bytes)

$check = [IO.File]::ReadAllBytes($DllPath)
$prefix = [Text.Encoding]::ASCII.GetBytes($newSignatureText)
if ((Find-ByteSequence $check $prefix).Count -ne 1) { throw 'Patched AOB signature verification failed.' }
if ((Find-ByteSequence $check $newPatch).Count -ne 1) { throw 'Patched bytes verification failed.' }

[PSCustomObject]@{
    Dll = $DllPath
    GameVersion = $GameVersion
    SignatureOffset = $sigOffset
    PatchBytesOffset = $patchOffset
    SHA256 = (Get-FileHash -LiteralPath $DllPath -Algorithm SHA256).Hash
}
