Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne "STA") {
    $pwsh = (Get-Command powershell.exe).Source
    Start-Process -FilePath $pwsh -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-STA",
        "-File", "`"$PSCommandPath`""
    )
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Remove-Item Alias:R -Force -ErrorAction SilentlyContinue

function R {
    param([string]$Value)
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Value))
}

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
                Proto      = $parts[0]
                Local      = $parts[1]
                Remote     = $parts[2]
                State      = $parts[3]
                PID        = $pidValue
                Process    = $processes[[string]$pidValue]
                RemotePort = Get-Port $parts[2]
                ObservedAt = Get-Date
            }
        }
        elseif ($parts[0] -eq "UDP" -and $parts.Count -ge 4) {
            $pidValue = $parts[3]
            $rows += [PSCustomObject]@{
                Proto      = $parts[0]
                Local      = $parts[1]
                Remote     = $parts[2]
                State      = "OPEN"
                PID        = $pidValue
                Process    = $processes[[string]$pidValue]
                RemotePort = Get-Port $parts[2]
                ObservedAt = Get-Date
            }
        }
    }

    return $rows
}

function New-ConnectionKey {
    param($Row)
    return "$($Row.Proto)|$($Row.Local)|$($Row.Remote)|$($Row.State)|$($Row.PID)"
}

function Group-Count {
    param(
        [object[]]$Items,
        [string]$Property,
        [int]$Limit = 50
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

function Get-EndpointHost {
    param([string]$Endpoint)

    if ([string]::IsNullOrWhiteSpace($Endpoint) -or $Endpoint -eq "*:*") { return "" }
    $clean = $Endpoint.Trim()

    if ($clean.StartsWith("[")) {
        $closing = $clean.LastIndexOf("]")
        if ($closing -gt 0) {
            return $clean.Substring(1, $closing - 1)
        }
    }

    $lastColon = $clean.LastIndexOf(":")
    if ($lastColon -lt 0) { return $clean }
    return $clean.Substring(0, $lastColon)
}

function Test-LocalOrPrivateHost {
    param([string]$HostValue)

    if ([string]::IsNullOrWhiteSpace($HostValue)) { return $true }
    if ($HostValue -eq "*" -or $HostValue -eq "0.0.0.0" -or $HostValue -eq "::") { return $true }
    if ($HostValue -eq "127.0.0.1" -or $HostValue -eq "::1" -or $HostValue -eq "localhost") { return $true }
    if ($HostValue.StartsWith("10.")) { return $true }
    if ($HostValue.StartsWith("192.168.")) { return $true }
    if ($HostValue -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.") { return $true }
    if ($HostValue.StartsWith("169.254.")) { return $true }
    if ($HostValue.StartsWith("fe80:")) { return $true }
    return $false
}

function Add-AnalysisRow {
    param(
        [object[]]$Rows,
        [string]$Level,
        [string]$Finding,
        [string]$Details
    )

    $Rows += [PSCustomObject]@{
        Level   = $Level
        Finding = $Finding
        Details = $Details
    }
    return $Rows
}

function Get-AnalysisRows {
    param(
        [object[]]$Connections,
        [object[]]$AdapterRows
    )

    $rows = @()
    $externalConnections = @(
        $Connections |
            Where-Object {
                $remoteHost = Get-EndpointHost $_.Remote
                -not (Test-LocalOrPrivateHost $remoteHost)
            }
    )
    $established = @($Connections | Where-Object { $_.State -eq "ESTABLISHED" })
    $listening = @($Connections | Where-Object { $_.State -eq "LISTENING" })
    $waiting = @($Connections | Where-Object { $_.State -in @("CLOSE_WAIT", "TIME_WAIT") })
    $udpOpen = @($Connections | Where-Object { $_.Proto -eq "UDP" })
    $activeAdapters = @($AdapterRows | Where-Object { ($_.ReceivedBytes + $_.SentBytes) -gt 0 })
    $topAdapter = @($activeAdapters | Sort-Object { $_.ReceivedBytes + $_.SentBytes } -Descending | Select-Object -First 1)
    $topProcesses = @(Group-Count $Connections "Process" 5)
    $topExternalProcesses = @(Group-Count $externalConnections "Process" 5)
    $topPorts = @(Group-Count $externalConnections "RemotePort" 5)

    $rows = Add-AnalysisRow $rows (R "0JjQvdGE0L4=") (R "0J7QsdC70LDRgdGC0Ywg0YHQsdC+0YDQsA==") (
        (R "0J3QsNCx0LvRjtC00LXQvdC+IHswfSDRg9C90LjQutCw0LvRjNC90YvRhSDRgdC+0LrQtdGC0L7QsjogezF9INGD0YHRgtCw0L3QvtCy0LvQtdC90L3Ri9GFLCB7Mn0g0L/RgNC+0YHQu9GD0YjQuNCy0LDRjtGJ0LjRhSwgezN9IFVEUC/QvtGC0LrRgNGL0YLRi9GFLg==") -f
        $Connections.Count, $established.Count, $listening.Count, $udpOpen.Count
    )

    if ($topAdapter.Count -gt 0) {
        $adapter = $topAdapter[0]
        $rows = Add-AnalysisRow $rows (R "0JjQvdGE0L4=") (R "0J7RgdC90L7QstC90L7QuSDRgdC10YLQtdCy0L7QuSDQsNC00LDQv9GC0LXRgA==") (
            (R "ezB9OiDQv9C+0LvRg9GH0LXQvdC+IHsxfSwg0L7RgtC/0YDQsNCy0LvQtdC90L4gezJ9LCDQstGB0LXQs9C+IHszfS4=") -f
            $adapter.Adapter, $adapter.Received, $adapter.Sent, $adapter.Total
        )
    }
    else {
        $rows = Add-AnalysisRow $rows (R "0JfQsNC80LXRgtC60LA=") (R "0J3QtdGCINC/0YDQuNGA0L7RgdGC0LAg0YLRgNCw0YTQuNC60LAg0L/QviDQsNC00LDQv9GC0LXRgNCw0Lw=") (R "0JLQviDQstGA0LXQvNGPINGC0LXQutGD0YnQtdCz0L4g0L7QutC90LAg0LDQvdCw0LvQuNC30LAg0YHRh9C10YLRh9C40LrQuCDQuNC90YLQtdGA0YTQtdC50YHQvtCyINC90LUg0LjQt9C80LXQvdC40LvQuNGB0Ywu")
    }

    if ($externalConnections.Count -gt 0) {
        $rows = Add-AnalysisRow $rows (R "0JjQvdGE0L4=") (R "0JLQvdC10YjQvdC40Lkg0YLRgNCw0YTQuNC6") (
            (R "ezB9INGB0L7QutC10YLQvtCyINGD0LrQsNC30YvQstCw0Y7RgiDQvdCwINC/0YPQsdC70LjRh9C90YvQtS/QvdC10LvQvtC60LDQu9GM0L3Ri9C1INGD0LTQsNC70LXQvdC90YvQtSDQsNC00YDQtdGB0LAu") -f $externalConnections.Count
        )
    }
    else {
        $rows = Add-AnalysisRow $rows (R "0JfQsNC80LXRgtC60LA=") (R "0JIg0L7RgdC90L7QstC90L7QvCDQu9C+0LrQsNC70YzQvdGL0Lkg0YLRgNCw0YTQuNC6") (R "0J/Rg9Cx0LvQuNGH0L3Ri9C1INGD0LTQsNC70LXQvdC90YvQtSDQsNC00YDQtdGB0LAg0L3QtSDQvtCx0L3QsNGA0YPQttC10L3Riy4g0JDQutGC0LjQstC90L7RgdGC0Ywg0LvQvtC60LDQu9GM0L3QsNGPLCDQstC90YPRgtGA0Lgg0YfQsNGB0YLQvdC+0Lkg0YHQtdGC0Lgg0LjQu9C4INGN0YLQviDQv9GA0L7RgdC70YPRiNC40LLQsNGO0YnQuNC1INGB0L7QutC10YLRiy4=")
    }

    if ($topProcesses.Count -gt 0) {
        $processText = ($topProcesses | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count }) -join ", "
        $rows = Add-AnalysisRow $rows (R "0JjQvdGE0L4=") (R "0KHQsNC80YvQtSDQt9Cw0LzQtdGC0L3Ri9C1INC/0YDQvtGG0LXRgdGB0Ys=") $processText
    }

    if ($topExternalProcesses.Count -gt 0) {
        $processText = ($topExternalProcesses | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count }) -join ", "
        $rows = Add-AnalysisRow $rows (R "0J/RgNC+0LLQtdGA0LjRgtGM") (R "0J/RgNC+0YbQtdGB0YHRiyDRgSDQstC90LXRiNC90LjQvNC4INC/0L7QtNC60LvRjtGH0LXQvdC40Y/QvNC4") $processText
    }

    if ($topPorts.Count -gt 0) {
        $portText = ($topPorts | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count }) -join ", "
        $rows = Add-AnalysisRow $rows (R "0JjQvdGE0L4=") (R "0KfQsNGB0YLRi9C1INCy0L3QtdGI0L3QuNC1INC/0L7RgNGC0Ys=") $portText
    }

    $closeWait = @($Connections | Where-Object { $_.State -eq "CLOSE_WAIT" })
    if ($closeWait.Count -gt 0) {
        $processText = (Group-Count $closeWait "Process" 5 | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count }) -join ", "
        $rows = Add-AnalysisRow $rows (R "0J/RgNC+0LLQtdGA0LjRgtGM") (R "0KHQvtC60LXRgtGLIENMT1NFX1dBSVQ=") (
            (R "ezB9INGB0L7QutC10YLQvtCyINC+0LbQuNC00LDRjtGCINC30LDQutGA0YvRgtC40Y8g0LvQvtC60LDQu9GM0L3Ri9C8INC/0YDQuNC70L7QttC10L3QuNC10LwuINCf0YDQvtGG0LXRgdGB0Ys6IHsxfS4=") -f $closeWait.Count, $processText
        )
    }

    if ($waiting.Count -gt 30) {
        $rows = Add-AnalysisRow $rows (R "0JfQsNC80LXRgtC60LA=") (R "0JzQvdC+0LPQviDQutC+0YDQvtGC0LrQuNGFINGB0L7QtdC00LjQvdC10L3QuNC5") (
            (R "ezB9INGB0L7QutC10YLQvtCyINC90LDRhdC+0LTRj9GC0YHRjyDQsiBUSU1FX1dBSVQvQ0xPU0VfV0FJVC4g0K3RgtC+INC+0LHRi9GH0L3QviDQtNC70Y8g0LHRgNCw0YPQt9C10YDQvtCyLCDQvNC10YHRgdC10L3QtNC20LXRgNC+0LIg0Lgg0LrQu9C40LXQvdGC0L7QsiDQvtCx0L3QvtCy0LvQtdC90LjQuS4=") -f $waiting.Count
        )
    }

    $nonWebExternal = @(
        $externalConnections |
            Where-Object {
                $_.RemotePort -notin @("80", "443", "53", "123", "*", "0")
            }
    )
    if ($nonWebExternal.Count -gt 0) {
        $portText = (Group-Count $nonWebExternal "RemotePort" 5 | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count }) -join ", "
        $rows = Add-AnalysisRow $rows (R "0J/RgNC+0LLQtdGA0LjRgtGM") (R "0J3QtdGB0YLQsNC90LTQsNGA0YLQvdGL0LUg0LLQvdC10YjQvdC40LUg0L/QvtGA0YLRiw==") (
            (R "ezB9INGB0L7QutC10YLQvtCyINC40YHQv9C+0LvRjNC30YPRjtGCINC/0L7RgNGC0Ysg0LLQvdC1INGC0LjQv9C40YfQvdC+0LPQviB3ZWIvRE5TL3RpbWUt0YLRgNCw0YTQuNC60LAuINCf0L7RgNGC0Ys6IHsxfS4=") -f $nonWebExternal.Count, $portText
        )
    }

    $unknownProcesses = @($Connections | Where-Object { [string]::IsNullOrWhiteSpace($_.Process) })
    if ($unknownProcesses.Count -gt 0) {
        $rows = Add-AnalysisRow $rows (R "0JfQsNC80LXRgtC60LA=") (R "0J3QtdC40LfQstC10YHRgtC90YvQtSDQv9GA0L7RhtC10YHRgdGL") (
            (R "ezB9INGB0L7QutC10YLQvtCyINC90LUg0YPQtNCw0LvQvtGB0Ywg0YHQstGP0LfQsNGC0Ywg0YEg0LjQvNC10L3QtdC8INC/0YDQvtGG0LXRgdGB0LAuINCn0LDRgdGC0L4g0Y3RgtC+INC30L3QsNGH0LjRgiwg0YfRgtC+INC/0YDQvtGG0LXRgdGBINC30LDQstC10YDRiNC40LvRgdGPINC00L4g0LrQvtC90YbQsCDQstGL0LHQvtGA0LrQuC4=") -f $unknownProcesses.Count
        )
    }

    return $rows
}

function Set-GridData {
    param(
        [System.Windows.Forms.DataGridView]$Grid,
        [object[]]$Rows,
        [string[]]$Columns = @()
    )

    $Grid.SuspendLayout()
    $Grid.DataSource = $null
    $Grid.Rows.Clear()
    $Grid.Columns.Clear()

    if ($Columns.Count -eq 0 -and $Rows.Count -gt 0) {
        $Columns = @($Rows[0].PSObject.Properties.Name)
    }

    foreach ($column in $Columns) {
        [void]$Grid.Columns.Add($column, $column)
        switch ($column) {
            "Level" { $Grid.Columns[$column].HeaderText = R "0KPRgNC+0LLQtdC90Yw=" }
            "Finding" { $Grid.Columns[$column].HeaderText = R "0JLRi9Cy0L7QtA==" }
            "Details" { $Grid.Columns[$column].HeaderText = R "0J/QvtC00YDQvtCx0L3QvtGB0YLQuA==" }
            "Adapter" { $Grid.Columns[$column].HeaderText = R "0JDQtNCw0L/RgtC10YA=" }
            "Status" { $Grid.Columns[$column].HeaderText = R "0KHRgtCw0YLRg9GB" }
            "Received" { $Grid.Columns[$column].HeaderText = R "0J/QvtC70YPRh9C10L3Qvg==" }
            "Sent" { $Grid.Columns[$column].HeaderText = R "0J7RgtC/0YDQsNCy0LvQtdC90L4=" }
            "Total" { $Grid.Columns[$column].HeaderText = R "0JLRgdC10LPQvg==" }
            "Name" { $Grid.Columns[$column].HeaderText = R "0J3QsNC30LLQsNC90LjQtQ==" }
            "Count" { $Grid.Columns[$column].HeaderText = R "0JrQvtC70LjRh9C10YHRgtCy0L4=" }
            "ObservedAt" { $Grid.Columns[$column].HeaderText = R "0JfQsNC80LXRh9C10L3Qvg==" }
            "Proto" { $Grid.Columns[$column].HeaderText = R "0J/RgNC+0YLQvtC60L7Quw==" }
            "Local" { $Grid.Columns[$column].HeaderText = R "0JvQvtC60LDQu9GM0L3Ri9C5INCw0LTRgNC10YE=" }
            "Remote" { $Grid.Columns[$column].HeaderText = R "0KPQtNCw0LvQtdC90L3Ri9C5INCw0LTRgNC10YE=" }
            "State" { $Grid.Columns[$column].HeaderText = R "0KHQvtGB0YLQvtGP0L3QuNC1" }
            "PID" { $Grid.Columns[$column].HeaderText = R "UElE" }
            "Process" { $Grid.Columns[$column].HeaderText = R "0J/RgNC+0YbQtdGB0YE=" }
        }
    }

    foreach ($row in $Rows) {
        $values = foreach ($column in $Columns) {
            [string]$row.$column
        }
        [void]$Grid.Rows.Add([object[]]$values)
    }

    $Grid.AutoResizeColumns([System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::DisplayedCells)
    if ($Grid.Columns.Contains("Details")) {
        $Grid.Columns["Details"].AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
    }
    $Grid.ResumeLayout()
}

function Get-AdapterRows {
    param(
        [object[]]$StartRows,
        [object[]]$EndRows
    )

    foreach ($start in $StartRows) {
        $end = $EndRows | Where-Object { $_.Name -eq $start.Name } | Select-Object -First 1
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
}

function Update-Grids {
    try {
        $connections = @($capture.Connections.Values)
        $adapterRows = @(Get-AdapterRows -StartRows $capture.AdapterStart -EndRows @(Get-AdapterStats))

        $visibleAdapterRows = @(
            $adapterRows |
                Sort-Object { $_.ReceivedBytes + $_.SentBytes } -Descending |
                Select-Object Adapter, Status, Received, Sent, Total
        )

        Set-GridData -Grid $analysisGrid -Rows @(Get-AnalysisRows -Connections $connections -AdapterRows $adapterRows) -Columns @("Level", "Finding", "Details")
        Set-GridData -Grid $adapterGrid -Rows $visibleAdapterRows -Columns @("Adapter", "Status", "Received", "Sent", "Total")

        Set-GridData -Grid $processGrid -Rows @(Group-Count $connections "Process" 100) -Columns @("Name", "Count")
        Set-GridData -Grid $stateGrid -Rows @(Group-Count $connections "State" 100) -Columns @("Name", "Count")
        Set-GridData -Grid $portGrid -Rows @(Group-Count $connections "RemotePort" 100) -Columns @("Name", "Count")
        Set-GridData -Grid $connectionGrid -Rows @(
            $connections |
                Sort-Object ObservedAt |
                Select-Object ObservedAt, Proto, Local, Remote, State, PID, Process
        ) -Columns @("ObservedAt", "Proto", "Local", "Remote", "State", "PID", "Process")
    }
    catch {
        $statusLabel.Text = (R "0J7RiNC40LHQutCwINC+0LHQvdC+0LLQu9C10L3QuNGPINGC0LDQsdC70LjRhjogezB9") -f $_.Exception.Message
    }
}

function New-Grid {
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = "Fill"
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AutoSizeColumnsMode = "Fill"
    $grid.BackgroundColor = [System.Drawing.Color]::White
    $grid.ColumnHeadersVisible = $true
    $grid.DefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::True
    $grid.AutoSizeRowsMode = [System.Windows.Forms.DataGridViewAutoSizeRowsMode]::DisplayedCells
    $grid.SelectionMode = "FullRowSelect"
    $grid.MultiSelect = $false
    $grid.RowHeadersVisible = $false
    return $grid
}

$capture = @{
    Running     = $false
    Duration    = 60
    StartedAt   = $null
    AdapterStart = @()
    Connections = @{}
    Samples     = 0
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "TrafficChecker"
$form.StartPosition = "CenterScreen"
$form.MinimumSize = New-Object System.Drawing.Size(900, 600)
$form.Size = New-Object System.Drawing.Size(1060, 720)

$root = New-Object System.Windows.Forms.TableLayoutPanel
$root.Dock = "Fill"
$root.RowCount = 3
$root.ColumnCount = 1
[void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 58)))
[void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34)))
[void]$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$form.Controls.Add($root)

$toolbar = New-Object System.Windows.Forms.FlowLayoutPanel
$toolbar.Dock = "Fill"
$toolbar.Padding = New-Object System.Windows.Forms.Padding(12, 12, 12, 8)
$toolbar.WrapContents = $false
$root.Controls.Add($toolbar, 0, 0)

$durationLabel = New-Object System.Windows.Forms.Label
$durationLabel.Text = R "0JLRgNC10LzRjyDQsNC90LDQu9C40LfQsDo="
$durationLabel.AutoSize = $true
$durationLabel.Margin = New-Object System.Windows.Forms.Padding(0, 6, 8, 0)
$toolbar.Controls.Add($durationLabel)

$durationBox = New-Object System.Windows.Forms.ComboBox
$durationBox.DropDownStyle = "DropDownList"
$durationBox.Width = 150
$durationBox.Items.AddRange(@(
    (R "MTUg0YHQtdC60YPQvdC0"),
    (R "MzAg0YHQtdC60YPQvdC0"),
    (R "MSDQvNC40L3Rg9GC0LA="),
    (R "MyDQvNC40L3Rg9GC0Ys="),
    (R "NSDQvNC40L3Rg9GC")
))
$durationBox.SelectedIndex = 2
$toolbar.Controls.Add($durationBox)

$startButton = New-Object System.Windows.Forms.Button
$startButton.Text = R "0JfQsNC/0YPRgdGC0LjRgtGM"
$startButton.Width = 120
$startButton.Height = 28
$startButton.Margin = New-Object System.Windows.Forms.Padding(18, 0, 6, 0)
$toolbar.Controls.Add($startButton)

$saveButton = New-Object System.Windows.Forms.Button
$saveButton.Text = R "0KHQvtGF0YDQsNC90LjRgtGMIENTVg=="
$saveButton.Width = 130
$saveButton.Height = 28
$saveButton.Enabled = $false
$toolbar.Controls.Add($saveButton)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = R "0JPQvtGC0L7QstC+Lg=="
$statusLabel.AutoSize = $true
$statusLabel.Margin = New-Object System.Windows.Forms.Padding(18, 6, 0, 0)
$toolbar.Controls.Add($statusLabel)

$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Dock = "Fill"
$progress.Minimum = 0
$progress.Maximum = 100
$root.Controls.Add($progress, 0, 1)

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = "Fill"
$root.Controls.Add($tabs, 0, 2)

$analysisTab = New-Object System.Windows.Forms.TabPage
$analysisTab.Text = R "0JDQvdCw0LvQuNC3"
$adapterTab = New-Object System.Windows.Forms.TabPage
$adapterTab.Text = R "0JDQtNCw0L/RgtC10YDRiw=="
$processTab = New-Object System.Windows.Forms.TabPage
$processTab.Text = R "0J/RgNC+0YbQtdGB0YHRiw=="
$stateTab = New-Object System.Windows.Forms.TabPage
$stateTab.Text = R "0KHQvtGB0YLQvtGP0L3QuNGP"
$portTab = New-Object System.Windows.Forms.TabPage
$portTab.Text = R "0J/QvtGA0YLRiw=="
$connectionTab = New-Object System.Windows.Forms.TabPage
$connectionTab.Text = R "0KHQvtC10LTQuNC90LXQvdC40Y8="
$tabs.Controls.AddRange(@($analysisTab, $adapterTab, $processTab, $stateTab, $portTab, $connectionTab))

$analysisGrid = New-Grid
$adapterGrid = New-Grid
$processGrid = New-Grid
$stateGrid = New-Grid
$portGrid = New-Grid
$connectionGrid = New-Grid
$analysisTab.Controls.Add($analysisGrid)
$adapterTab.Controls.Add($adapterGrid)
$processTab.Controls.Add($processGrid)
$stateTab.Controls.Add($stateGrid)
$portTab.Controls.Add($portGrid)
$connectionTab.Controls.Add($connectionGrid)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000

function Get-SelectedDuration {
    switch ($durationBox.SelectedIndex) {
        0 { return 15 }
        1 { return 30 }
        2 { return 60 }
        3 { return 180 }
        4 { return 300 }
        default { return 60 }
    }
}

function Stop-Capture {
    $timer.Stop()
    $capture.Running = $false
    $startButton.Enabled = $true
    $durationBox.Enabled = $true
    $saveButton.Enabled = $true
    $progress.Value = 100

    $connections = @($capture.Connections.Values)
    Update-Grids
    $statusLabel.Text = (R "0JPQvtGC0L7QstC+LiDQndCw0LnQtNC10L3QviDRgdC+0LXQtNC40L3QtdC90LjQuTogezB9Lg==") -f $connections.Count
}

$timer.Add_Tick({
    if (-not $capture.Running) { return }

    foreach ($row in Get-NetstatSnapshot) {
        $key = New-ConnectionKey $row
        if (-not $capture.Connections.ContainsKey($key)) {
            $capture.Connections[$key] = $row
        }
    }

    $capture.Samples++
    $elapsed = [int]((Get-Date) - $capture.StartedAt).TotalSeconds
    $percent = [Math]::Min(100, [int](($elapsed / $capture.Duration) * 100))
    $progress.Value = $percent
    $left = [Math]::Max(0, $capture.Duration - $elapsed)
    $statusLabel.Text = (R "0JjQtNC10YIg0LDQvdCw0LvQuNC3Li4uINC+0YHRgtCw0LvQvtGB0YwgezB9INGB0LXQui4=") -f $left
    Update-Grids

    if ($elapsed -ge $capture.Duration) {
        Stop-Capture
    }
})

$startButton.Add_Click({
    $capture.Running = $true
    $capture.Duration = Get-SelectedDuration
    $capture.StartedAt = Get-Date
    $capture.AdapterStart = @(Get-AdapterStats)
    $capture.Connections = @{}
    $capture.Samples = 0

    $progress.Value = 0
    $startButton.Enabled = $false
    $durationBox.Enabled = $false
    $saveButton.Enabled = $false
    $statusLabel.Text = R "0JjQtNC10YIg0LDQvdCw0LvQuNC3Li4u"

    Set-GridData -Grid $analysisGrid -Rows @() -Columns @("Level", "Finding", "Details")
    Set-GridData -Grid $adapterGrid -Rows @() -Columns @("Adapter", "Status", "Received", "Sent", "Total")
    Set-GridData -Grid $processGrid -Rows @() -Columns @("Name", "Count")
    Set-GridData -Grid $stateGrid -Rows @() -Columns @("Name", "Count")
    Set-GridData -Grid $portGrid -Rows @() -Columns @("Name", "Count")
    Set-GridData -Grid $connectionGrid -Rows @() -Columns @("ObservedAt", "Proto", "Local", "Remote", "State", "PID", "Process")

    foreach ($row in Get-NetstatSnapshot) {
        $key = New-ConnectionKey $row
        if (-not $capture.Connections.ContainsKey($key)) {
            $capture.Connections[$key] = $row
        }
    }
    Update-Grids
    $timer.Start()
})

$saveButton.Add_Click({
    $connections = @($capture.Connections.Values)
    if ($connections.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show((R "0J3QtdGCINC00LDQvdC90YvRhSDQtNC70Y8g0YHQvtGF0YDQsNC90LXQvdC40Y8u"), "TrafficChecker") | Out-Null
        return
    }

    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Filter = R "Q1NWLdGE0LDQudC70YsgKCouY3N2KXwqLmNzdnzQktGB0LUg0YTQsNC50LvRiyAoKi4qKXwqLio="
    $dialog.FileName = "traffic-report.csv"
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $connections |
            Sort-Object ObservedAt, Proto, Local, Remote |
            Export-Csv -Path $dialog.FileName -NoTypeInformation -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show(((R "Q1NWINGB0L7RhdGA0LDQvdC10L06IHswfQ==") -f $dialog.FileName), "TrafficChecker") | Out-Null
    }
})

[void]$form.ShowDialog()
