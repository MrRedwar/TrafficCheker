param(
    [ValidateRange(1, 86400)]
    [int]$DurationSeconds = 60,

    [ValidateRange(1, 3600)]
    [int]$IntervalSeconds = 5,

    [ValidateRange(1, 200)]
    [int]$Top = 25,

    [string]$CsvPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-AdapterStats {
    [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
        ForEach-Object {
            $stats = $_.GetIPv4Statistics()
            [PSCustomObject]@{
                Name          = $_.Name
                Status        = $_.OperationalStatus.ToString()
                Type          = $_.NetworkInterfaceType.ToString()
                ReceivedBytes = [int64]$stats.BytesReceived
                SentBytes     = [int64]$stats.BytesSent
            }
        }
}

function Get-ProcessMap {
    $map = @{}
    Get-Process | ForEach-Object {
        $map[[string]$_.Id] = $_.ProcessName
    }
    return $map
}

function ConvertTo-Size {
    param([int64]$Bytes)

    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Get-Port {
    param([string]$Endpoint)

    if ($Endpoint -eq "*:*") { return "*" }
    $clean = $Endpoint.Trim()
    $lastColon = $clean.LastIndexOf(":")
    if ($lastColon -lt 0) { return "" }
    return $clean.Substring($lastColon + 1)
}

function Get-NetstatSnapshot {
    $processes = Get-ProcessMap
    $rows = @()

    netstat -ano | ForEach-Object {
        $line = $_.Trim()
        if ($line -notmatch "^(TCP|UDP)\s+") { return }

        $parts = $line -split "\s+"
        if ($parts[0] -eq "TCP" -and $parts.Count -ge 5) {
            $pidValue = $parts[4]
            $rows += [PSCustomObject]@{
                Proto       = $parts[0]
                Local       = $parts[1]
                Remote      = $parts[2]
                State       = $parts[3]
                PID         = $pidValue
                Process     = $processes[[string]$pidValue]
                RemotePort  = Get-Port $parts[2]
                ObservedAt  = Get-Date
            }
        }
        elseif ($parts[0] -eq "UDP" -and $parts.Count -ge 4) {
            $pidValue = $parts[3]
            $rows += [PSCustomObject]@{
                Proto       = $parts[0]
                Local       = $parts[1]
                Remote      = $parts[2]
                State       = "OPEN"
                PID         = $pidValue
                Process     = $processes[[string]$pidValue]
                RemotePort  = Get-Port $parts[2]
                ObservedAt  = Get-Date
            }
        }
    }

    return $rows
}

function Group-Count {
    param(
        [object[]]$Items,
        [string]$Property,
        [int]$Limit
    )

    $Items |
        Group-Object -Property $Property |
        Sort-Object Count -Descending |
        Select-Object -First $Limit |
        ForEach-Object {
            [PSCustomObject]@{
                Name  = if ([string]::IsNullOrWhiteSpace($_.Name)) { "(unknown)" } else { $_.Name }
                Count = $_.Count
            }
        }
}

function New-ConnectionKey {
    param($Row)
    return "$($Row.Proto)|$($Row.Local)|$($Row.Remote)|$($Row.State)|$($Row.PID)"
}

if ($IntervalSeconds -gt $DurationSeconds) {
    $IntervalSeconds = $DurationSeconds
}

$startedAt = Get-Date
$adapterStart = Get-AdapterStats
$observedConnections = @{}
$samples = 0
$timer = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "TrafficChecker capture started"
Write-Host ("Duration: {0}s, interval: {1}s" -f $DurationSeconds, $IntervalSeconds)
Write-Host ""

while ($timer.Elapsed.TotalSeconds -lt $DurationSeconds) {
    $samples++
    foreach ($row in Get-NetstatSnapshot) {
        $key = New-ConnectionKey $row
        if (-not $observedConnections.ContainsKey($key)) {
            $observedConnections[$key] = $row
        }
    }

    $remaining = $DurationSeconds - [int][Math]::Floor($timer.Elapsed.TotalSeconds)
    if ($remaining -le 0) { break }
    Start-Sleep -Seconds ([Math]::Min($IntervalSeconds, $remaining))
}

$endedAt = Get-Date
$adapterEnd = Get-AdapterStats
$connections = @($observedConnections.Values)

$adapterRows = foreach ($start in $adapterStart) {
    $end = $adapterEnd | Where-Object { $_.Name -eq $start.Name } | Select-Object -First 1
    if ($null -eq $end) { continue }

    $receivedDelta = [Math]::Max(0, [int64]$end.ReceivedBytes - [int64]$start.ReceivedBytes)
    $sentDelta = [Math]::Max(0, [int64]$end.SentBytes - [int64]$start.SentBytes)
    if ($receivedDelta -eq 0 -and $sentDelta -eq 0) { continue }

    [PSCustomObject]@{
        Adapter       = $start.Name
        Status        = $end.Status
        Received      = ConvertTo-Size $receivedDelta
        Sent          = ConvertTo-Size $sentDelta
        Total         = ConvertTo-Size ($receivedDelta + $sentDelta)
        ReceivedBytes = $receivedDelta
        SentBytes     = $sentDelta
    }
}

$connectionRows = $connections |
    Sort-Object Proto, Process, Remote |
    Select-Object -First $Top Proto, Local, Remote, State, PID, Process

Write-Host "Capture summary"
Write-Host ("Started: {0}" -f $startedAt)
Write-Host ("Ended:   {0}" -f $endedAt)
Write-Host ("Samples: {0}" -f $samples)
Write-Host ("Unique connections observed: {0}" -f $connections.Count)
Write-Host ""

Write-Host "Adapter traffic"
if (@($adapterRows).Count -eq 0) {
    Write-Host "No adapter byte changes were observed."
}
else {
    $adapterRows |
        Sort-Object { $_.ReceivedBytes + $_.SentBytes } -Descending |
        Select-Object Adapter, Status, Received, Sent, Total |
        Format-Table -AutoSize
}

Write-Host ""
Write-Host "Top processes by observed sockets"
Group-Count $connections "Process" $Top | Format-Table -AutoSize

Write-Host ""
Write-Host "Connection states"
Group-Count $connections "State" $Top | Format-Table -AutoSize

Write-Host ""
Write-Host "Remote ports"
Group-Count $connections "RemotePort" $Top | Format-Table -AutoSize

Write-Host ""
Write-Host "Observed connections"
if (@($connectionRows).Count -eq 0) {
    Write-Host "No TCP/UDP connections were observed."
}
else {
    $connectionRows | Format-Table -AutoSize
}

if (-not [string]::IsNullOrWhiteSpace($CsvPath)) {
    $connections |
        Sort-Object ObservedAt, Proto, Local, Remote |
        Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host ("CSV saved: {0}" -f (Resolve-Path $CsvPath))
}
