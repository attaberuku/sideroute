# Sideroute Windows installer for the command line. Most people simply download and run
# SiderouteSetup.exe; this does the same unattended:
#
#   irm https://raw.githubusercontent.com/attaberuku/sideroute/main/windows/install.ps1 | iex
#
# It downloads SiderouteSetup.exe from the latest release (checking its SHA-256), asks for a pairing
# code (Enter = Cloudflare WARP) and runs `SiderouteSetup.exe setup --quiet`.
#
# Options:  -Code <pairing code | warp>   -Exe <local SiderouteSetup.exe>   -NoAutostart   -Uninstall
param(
    [switch]$Uninstall,
    [switch]$NoAutostart,
    [string]$Code = $env:SIDEROUTE_CODE,
    [string]$Exe
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Repo = if ($env:SIDEROUTE_REPO) { $env:SIDEROUTE_REPO } else { 'attaberuku/sideroute' }

function Fail($m) { Write-Host "error: $m" -ForegroundColor Red; exit 1 }

if ($Uninstall) {
    $installed = Join-Path $env:ProgramFiles 'Sideroute\Sideroute.exe'
    if (-not (Test-Path $installed)) { Fail 'Sideroute is not installed' }
    Start-Process $installed -ArgumentList 'uninstall' -Wait
    return
}

if (-not $Exe) {
    $base = "https://github.com/$Repo/releases/latest/download"
    $Exe = Join-Path ([IO.Path]::GetTempPath()) 'SiderouteSetup.exe'
    Write-Host '==> downloading SiderouteSetup.exe'
    $sums = (Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS").Content
    $line = ($sums -split "`n") | Where-Object { $_ -match ' SiderouteSetup\.exe$' } | Select-Object -First 1
    if (-not $line) { Fail 'the release has no Windows build' }
    Invoke-WebRequest -UseBasicParsing "$base/SiderouteSetup.exe" -OutFile $Exe
    if ((Get-FileHash -Algorithm SHA256 $Exe).Hash.ToLower() -ne ($line -split '\s+')[0].ToLower()) { Fail 'checksum mismatch' }
}

$argsList = @('setup', '--quiet')
# an existing installation keeps its pairing unless a code is given
$already = Test-Path (Join-Path $env:ProgramFiles 'Sideroute\Sideroute.exe')
if (-not $Code -and -not $already) {
    Write-Host 'Paste the pairing code shown by your server (sr1:...),'
    $Code = Read-Host 'or just press Enter to use Cloudflare WARP (free, no server needed)'
    if (-not $Code.Trim()) { $Code = 'warp' }
}
if ($Code -eq 'warp') { $argsList += '--warp' } elseif ($Code) { $argsList += @('--code', $Code.Trim()) }
if ($NoAutostart) { $argsList += '--no-autostart' }

# started elevated directly (UAC prompt) so that -Wait waits for the actual installation
$p = Start-Process (Resolve-Path $Exe) -ArgumentList $argsList -Verb RunAs -Wait -PassThru
if ($p.ExitCode -ne 0) { Fail "setup failed (exit code $($p.ExitCode))" }
Write-Host '==> Sideroute is installed and running (see its icon in the notification area).' -ForegroundColor Green
