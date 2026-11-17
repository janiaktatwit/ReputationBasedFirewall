<#
.SYNOPSIS
  Classifies each Source IP as BENIGN-only, MALICIOUS-only, or MIXED
  based on the Label column, and writes the result to a text file.

.EXAMPLE
  .\Classify-SourceIPs.ps1 -Path .\traffic.csv -OutFile .\ip_summary.txt
#>
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$OutFile = ".\ip_summary.txt"
)

$reader = New-Object System.IO.StreamReader($Path, [System.Text.Encoding]::GetEncoding('iso-8859-1'))

try {
    # Find column positions from the header (trim the stray spaces)
    $header = $reader.ReadLine().Split(',') | ForEach-Object { $_.Trim() }
    $ipIdx    = [Array]::IndexOf($header, 'Source IP')
    if ($ipIdx -lt 0) { $ipIdx = [Array]::IndexOf($header, 'Src IP') }
    $labelIdx = [Array]::IndexOf($header, 'Label')
    if ($ipIdx -lt 0 -or $labelIdx -lt 0) { throw "Could not find 'Source IP' and/or 'Label' columns in header." }

    $benign    = @{}   # ip -> count of benign flows
    $malicious = @{}   # ip -> count of malicious flows
    $attacks   = @{}   # ip -> hashtable of attack label -> count

    while ($null -ne ($line = $reader.ReadLine())) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $f = $line.Split(',')
        if ($f.Count -le $labelIdx) { continue }   # skip malformed lines

        $ip    = $f[$ipIdx].Trim()
        $label = $f[$f.Count - 1].Trim()           # Label is the last column

        if ($label -ieq 'BENIGN') {
            $benign[$ip] = 1 + [int]$benign[$ip]
        } else {
            $malicious[$ip] = 1 + [int]$malicious[$ip]
            if (-not $attacks.ContainsKey($ip)) { $attacks[$ip] = @{} }
            $attacks[$ip][$label] = 1 + [int]$attacks[$ip][$label]
        }
    }
}
finally { $reader.Close() }

# Build the categories
$allIps = @($benign.Keys) + @($malicious.Keys) | Sort-Object -Unique
$onlyBenign = @(); $onlyMal = @(); $mixed = @()

foreach ($ip in $allIps) {
    $b = [int]$benign[$ip]; $m = [int]$malicious[$ip]
    if     ($m -eq 0) { $onlyBenign += $ip }
    elseif ($b -eq 0) { $onlyMal    += $ip }
    else              { $mixed      += $ip }
}

function Format-Ip($ip) {
    $b = [int]$benign[$ip]; $m = [int]$malicious[$ip]
    $types = ''
    if ($attacks.ContainsKey($ip)) {
        $types = '  [' + (($attacks[$ip].GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ', ') + ']'
    }
    "{0,-18} benign={1,-8} malicious={2,-8}{3}" -f $ip, $b, $m, $types
}

$out = New-Object System.Collections.Generic.List[string]
$out.Add("Source IP traffic summary for: $Path")
$out.Add("Generated: $(Get-Date)")
$out.Add("Total unique source IPs: $($allIps.Count)")
$out.Add("")
$out.Add("=== BENIGN ONLY ($($onlyBenign.Count)) ===")
$onlyBenign | ForEach-Object { $out.Add((Format-Ip $_)) }
$out.Add("")
$out.Add("=== MALICIOUS ONLY ($($onlyMal.Count)) ===")
$onlyMal | ForEach-Object { $out.Add((Format-Ip $_)) }
$out.Add("")
$out.Add("=== MIXED ($($mixed.Count)) ===")
$mixed | ForEach-Object { $out.Add((Format-Ip $_)) }

$out | Set-Content -Path $OutFile -Encoding UTF8
Write-Host "Done. Results written to $OutFile"