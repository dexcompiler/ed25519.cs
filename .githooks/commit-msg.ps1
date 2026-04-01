param(
    [Parameter(Mandatory = $true)]
    [string]$MessageFile
)

$lines = Get-Content -LiteralPath $MessageFile
$filtered = foreach ($line in $lines) {
    if ($line -notmatch '^(?i)co-authored-by:\s') { $line }
}

while ($filtered.Count -gt 0 -and $filtered[-1] -eq '') {
    $filtered = $filtered[0..($filtered.Count - 2)]
}

if ($filtered.Count -eq 0) {
    Set-Content -LiteralPath $MessageFile -NoNewline -Value ''
}
else {
    Set-Content -LiteralPath $MessageFile -Value $filtered
}
