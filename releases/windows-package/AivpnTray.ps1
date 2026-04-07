Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = "Stop"
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:StateDir = Join-Path $env:APPDATA "AIVPN"
$script:ConfigPath = Join-Path $script:StateDir "tray-config.json"
$script:LogPath = Join-Path $script:StateDir "client.log"
$script:PidPath = Join-Path $script:StateDir "client.pid"
$script:ClientExe = Join-Path $script:AppRoot "aivpn-client.exe"
$script:StartHelper = Join-Path $script:AppRoot "start-client.ps1"
$script:StopHelper = Join-Path $script:AppRoot "stop-client.ps1"

New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null

function New-StatusIcon {
    param([string]$ColorName)

    $bitmap = New-Object System.Drawing.Bitmap 16, 16
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.Clear([System.Drawing.Color]::Transparent)

    $brush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromName($ColorName))
    $graphics.FillEllipse($brush, 2, 2, 12, 12)
    $graphics.DrawEllipse([System.Drawing.Pens]::White, 2, 2, 12, 12)

    $icon = [System.Drawing.Icon]::FromHandle($bitmap.GetHicon())

    $brush.Dispose()
    $graphics.Dispose()
    return $icon
}

function Get-Config {
    if (Test-Path $script:ConfigPath) {
        try {
            return Get-Content $script:ConfigPath -Raw | ConvertFrom-Json
        }
        catch {
        }
    }

    return [pscustomobject]@{
        connectionKey = ""
        fullTunnel = $true
    }
}

function Save-Config {
    param($Config)

    $Config | ConvertTo-Json | Set-Content -Path $script:ConfigPath -Encoding UTF8
}

function Get-ClientProcess {
    if (Test-Path $script:PidPath) {
        $pidValue = (Get-Content $script:PidPath -ErrorAction SilentlyContinue | Select-Object -First 1).Trim()
        if ($pidValue) {
            try {
                return Get-Process -Id ([int]$pidValue) -ErrorAction Stop
            }
            catch {
                Remove-Item $script:PidPath -Force -ErrorAction SilentlyContinue
            }
        }
    }

    return Get-Process -Name "aivpn-client" -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Update-TrayState {
    $proc = Get-ClientProcess
    if ($null -ne $proc) {
        $script:NotifyIcon.Icon = $script:ConnectedIcon
        $script:NotifyIcon.Text = "AIVPN: Connected"
        $script:StatusLabel.Text = "Status: Connected (PID=$($proc.Id))"
    }
    else {
        $script:NotifyIcon.Icon = $script:DisconnectedIcon
        $script:NotifyIcon.Text = "AIVPN: Disconnected"
        $script:StatusLabel.Text = "Status: Disconnected"
    }
}

function Show-SettingsWindow {
    $config = Get-Config

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "AIVPN"
    $form.Size = New-Object System.Drawing.Size(420, 255)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true

    $keyLabel = New-Object System.Windows.Forms.Label
    $keyLabel.Text = "Connection Key"
    $keyLabel.Location = New-Object System.Drawing.Point(15, 15)
    $keyLabel.AutoSize = $true

    $keyBox = New-Object System.Windows.Forms.TextBox
    $keyBox.Location = New-Object System.Drawing.Point(15, 38)
    $keyBox.Size = New-Object System.Drawing.Size(375, 90)
    $keyBox.Multiline = $true
    $keyBox.ScrollBars = "Vertical"
    $keyBox.Text = [string]$config.connectionKey

    $fullTunnelBox = New-Object System.Windows.Forms.CheckBox
    $fullTunnelBox.Location = New-Object System.Drawing.Point(15, 140)
    $fullTunnelBox.Size = New-Object System.Drawing.Size(180, 24)
    $fullTunnelBox.Text = "Use full tunnel"
    $fullTunnelBox.Checked = [bool]$config.fullTunnel

    $saveButton = New-Object System.Windows.Forms.Button
    $saveButton.Text = "Save"
    $saveButton.Location = New-Object System.Drawing.Point(234, 175)
    $saveButton.Size = New-Object System.Drawing.Size(75, 28)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = "Cancel"
    $cancelButton.Location = New-Object System.Drawing.Point(315, 175)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 28)

    $saveButton.Add_Click({
        $newConfig = [pscustomobject]@{
            connectionKey = $keyBox.Text.Trim()
            fullTunnel = $fullTunnelBox.Checked
        }
        Save-Config $newConfig
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })

    $cancelButton.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Close()
    })

    $form.Controls.AddRange(@($keyLabel, $keyBox, $fullTunnelBox, $saveButton, $cancelButton))
    [void]$form.ShowDialog()
}

function Start-Vpn {
    $config = Get-Config
    if (-not $config.connectionKey) {
        [System.Windows.Forms.MessageBox]::Show("Set a connection key first.", "AIVPN") | Out-Null
        Show-SettingsWindow
        $config = Get-Config
        if (-not $config.connectionKey) {
            return
        }
    }

    if (-not (Test-Path $script:ClientExe)) {
        [System.Windows.Forms.MessageBox]::Show("Missing aivpn-client.exe next to the tray app.", "AIVPN") | Out-Null
        return
    }

    $helperArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"{0}"' -f $script:StartHelper),
        "-InstallDir", ('"{0}"' -f $script:AppRoot),
        "-ConnectionKey", ('"{0}"' -f $config.connectionKey)
    )
    if ([bool]$config.fullTunnel) {
        $helperArgs += "-FullTunnel"
    }

    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList $helperArgs -Verb RunAs -WindowStyle Hidden | Out-Null
        Start-Sleep -Milliseconds 900
        Update-TrayState
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to start AIVPN: $($_.Exception.Message)", "AIVPN") | Out-Null
    }
}

function Stop-Vpn {
    $helperArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"{0}"' -f $script:StopHelper),
        "-InstallDir", ('"{0}"' -f $script:AppRoot)
    )

    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList $helperArgs -Verb RunAs -WindowStyle Hidden | Out-Null
        Start-Sleep -Milliseconds 700
        Update-TrayState
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to stop AIVPN: $($_.Exception.Message)", "AIVPN") | Out-Null
    }
}

function Open-Log {
    if (-not (Test-Path $script:LogPath)) {
        New-Item -ItemType File -Path $script:LogPath -Force | Out-Null
    }
    Start-Process -FilePath "notepad.exe" -ArgumentList ('"{0}"' -f $script:LogPath) | Out-Null
}

$script:DisconnectedIcon = New-StatusIcon -ColorName "IndianRed"
$script:ConnectedIcon = New-StatusIcon -ColorName "MediumSeaGreen"

$script:NotifyIcon = New-Object System.Windows.Forms.NotifyIcon
$script:NotifyIcon.Icon = $script:DisconnectedIcon
$script:NotifyIcon.Visible = $true
$script:NotifyIcon.Text = "AIVPN"

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$connectItem = $menu.Items.Add("Connect")
$disconnectItem = $menu.Items.Add("Disconnect")
$settingsItem = $menu.Items.Add("Settings")
$logItem = $menu.Items.Add("Open Log")
$menu.Items.Add("-") | Out-Null
$exitItem = $menu.Items.Add("Exit Tray")

$connectItem.Add_Click({ Start-Vpn })
$disconnectItem.Add_Click({ Stop-Vpn })
$settingsItem.Add_Click({ Show-SettingsWindow })
$logItem.Add_Click({ Open-Log })
$exitItem.Add_Click({
    $script:PollTimer.Stop()
    $script:NotifyIcon.Visible = $false
    [System.Windows.Forms.Application]::Exit()
})

$script:NotifyIcon.ContextMenuStrip = $menu
$script:NotifyIcon.Add_DoubleClick({ Show-SettingsWindow })

$statusForm = New-Object System.Windows.Forms.Form
$statusForm.Text = "AIVPN"
$statusForm.Size = New-Object System.Drawing.Size(360, 160)
$statusForm.StartPosition = "CenterScreen"
$statusForm.FormBorderStyle = "FixedDialog"
$statusForm.MaximizeBox = $false

$script:StatusLabel = New-Object System.Windows.Forms.Label
$script:StatusLabel.Location = New-Object System.Drawing.Point(18, 18)
$script:StatusLabel.Size = New-Object System.Drawing.Size(310, 24)
$script:StatusLabel.Text = "Status: Disconnected"

$settingsButton = New-Object System.Windows.Forms.Button
$settingsButton.Location = New-Object System.Drawing.Point(18, 56)
$settingsButton.Size = New-Object System.Drawing.Size(90, 30)
$settingsButton.Text = "Settings"
$settingsButton.Add_Click({ Show-SettingsWindow })

$connectButton = New-Object System.Windows.Forms.Button
$connectButton.Location = New-Object System.Drawing.Point(124, 56)
$connectButton.Size = New-Object System.Drawing.Size(90, 30)
$connectButton.Text = "Connect"
$connectButton.Add_Click({ Start-Vpn })

$disconnectButton = New-Object System.Windows.Forms.Button
$disconnectButton.Location = New-Object System.Drawing.Point(232, 56)
$disconnectButton.Size = New-Object System.Drawing.Size(90, 30)
$disconnectButton.Text = "Disconnect"
$disconnectButton.Add_Click({ Stop-Vpn })

$hintLabel = New-Object System.Windows.Forms.Label
$hintLabel.Location = New-Object System.Drawing.Point(18, 98)
$hintLabel.Size = New-Object System.Drawing.Size(310, 24)
$hintLabel.Text = "Close the window to keep AIVPN in the tray."

$statusForm.Controls.AddRange(@($script:StatusLabel, $settingsButton, $connectButton, $disconnectButton, $hintLabel))
$statusForm.Add_FormClosing({
    param($sender, $eventArgs)
    if ($eventArgs.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing) {
        $eventArgs.Cancel = $true
        $statusForm.Hide()
    }
})

$script:NotifyIcon.Add_Click({
    if ($statusForm.Visible) {
        $statusForm.Hide()
    }
    else {
        $statusForm.Show()
        $statusForm.Activate()
    }
})

$script:PollTimer = New-Object System.Windows.Forms.Timer
$script:PollTimer.Interval = 1500
$script:PollTimer.Add_Tick({ Update-TrayState })
$script:PollTimer.Start()

Update-TrayState
[System.Windows.Forms.Application]::Run()