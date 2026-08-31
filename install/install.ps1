# Install spill-guard from a published release, on Windows.
#
# The documented form is two steps -- download, read, run:
#
#   curl.exe -fsSLO https://github.com/karlkfi/claude-spill-guard/releases/latest/download/install.ps1
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# The one-liner that pipes this into a shell works and is not what the README
# leads with. For a tool whose whole pitch is that nothing leaves your machine,
# opening with "pipe this remote script into your shell" undercuts the claim
# before a reader reaches the second paragraph.
#
# This is install.sh's argument in PowerShell, and the verification is the same
# in the same order: the archive's sha256 against checksums.txt always, then
# the signature with cosign if it is installed, else `gh attestation verify`,
# and a refusal when neither is. The reasoning is in install.sh's header and in
# docs/design/distribution.md under "Settled"; it is not repeated here, because
# two copies of an argument are two things to keep in step.
#
# One thing genuinely differs. install.sh resolves `latest` by reading the URL
# curl's redirect landed on, because POSIX sh cannot parse JSON without a tool
# it may not have. PowerShell parses JSON as a language feature, so this asks
# the API instead.
#
# Windows PowerShell 5.1 is the floor: it ships in the box and is what a
# `powershell -File` invocation gets. So no ternaries, no `??`, and
# -UseBasicParsing on every web call.

[CmdletBinding()]
param(
    # The release to install, e.g. v1.2.3. Default: the latest.
    [string]$Version = '',
    # Where to install. Default: %LOCALAPPDATA%\spill-guard\bin.
    [string]$Dir = '',
    # Print which signature verifier would be used and exit; non-zero when
    # neither cosign nor gh is installed.
    [switch]$Verifier,
    # Fetch from this URL instead of the release, and do NOT verify the
    # signature. For exercising this script against artifacts no release has
    # published; it refuses a github.com URL, so it is not an install path.
    [string]$Rehearse = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Invoke-WebRequest's progress bar costs more than the download does on 5.1.
$ProgressPreference = 'SilentlyContinue'

$Repo = 'karlkfi/claude-spill-guard'
$Workflow = '.github/workflows/release.yml'
$OidcIssuer = 'https://token.actions.githubusercontent.com'

$NoVerifier = 'neither cosign nor gh is installed, so nothing here could establish that an archive came from this repository. The sha256 check answers corruption and not substitution, so it is not a fallback. Install one of them -- `winget install sigstore.cosign`, or gh from https://cli.github.com -- or install through Scoop, which pins the sha256 itself and asks you for no tool at all.'

# The console streams by name rather than Write-Host, which writes to the
# host's information stream: a caller capturing `... 2>&1` gets nothing from
# it, and the mutation controls in .github/workflows/release.yml assert on
# these exact messages. Same split as install.sh -- progress on stdout,
# refusals on stderr.
function Say([string]$m) { [Console]::Out.WriteLine("install.ps1: $m") }

function Die([string]$m) {
    [Console]::Error.WriteLine("install.ps1: $m")
    exit 1
}

# Which verifier this machine has, or $null. Resolved without touching the
# network, which is what lets -Verifier answer the question a refusal raises --
# and what gives the refusal path a seam CI can drive. No pull request can
# reach the verification itself: a real signature needs a real release, and the
# first one is a permanent version number.
function Get-Verifier {
    if (Get-Command cosign -ErrorAction SilentlyContinue) { return 'cosign' }
    if (Get-Command gh -ErrorAction SilentlyContinue) { return 'gh' }
    return $null
}

if ($Verifier) {
    $found = Get-Verifier
    if ($found) {
        Say "signatures would be verified with $found"
        exit 0
    }
    Die $NoVerifier
}

# 5.1 on an older host can still default to TLS 1.0, which github.com refuses.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # PowerShell 7 manages this itself and the property may not be settable.
}

# spill-guard ships no windows/arm64 build. Windows on ARM runs the x64 binary
# under emulation, so this installs amd64 and says so rather than refusing --
# and the `spill-guard version` call at the end is what actually decides
# whether it runs on this machine.
$procArch = $env:PROCESSOR_ARCHITEW6432
if (-not $procArch) { $procArch = $env:PROCESSOR_ARCHITECTURE }
switch ($procArch) {
    'AMD64' { $goarch = 'amd64' }
    'ARM64' {
        $goarch = 'amd64'
        Say 'this is an ARM64 machine and spill-guard ships no windows/arm64 build, so the amd64 one is being installed to run under x64 emulation.'
    }
    default { Die "$procArch is not an architecture spill-guard ships a Windows binary for: it ships windows/amd64." }
}

# A rehearsal is not an install path, and this is what stops it becoming one.
# The flag skips signature verification -- artifacts served from an arbitrary
# URL carry no release provenance to check -- so it must not be possible to aim
# it at the place a real install fetches from.
if ($Rehearse) {
    if ($Rehearse -match 'github\.com|githubusercontent\.com') {
        Die '-Rehearse refuses a github.com URL. It exists to exercise this script against artifacts no release has published, and it does not verify signatures, so pointing it at the real release would install an unverified archive from the one place that can be verified.'
    }
    if (-not $Version) {
        Die '-Rehearse needs -Version too: there is no `latest` to resolve at a URL that is not a GitHub release.'
    }
}

if (-not $Version) {
    try {
        $latest = Invoke-RestMethod -UseBasicParsing -Uri "https://api.github.com/repos/$Repo/releases/latest"
        $Version = $latest.tag_name
    } catch {
        Die "could not read the latest release from the GitHub API, so there is no tag to install. Pass -Version vX.Y.Z. ($($_.Exception.Message))"
    }
    if (-not $Version) {
        Die 'the GitHub API named a latest release with no tag. Pass -Version vX.Y.Z.'
    }
    Say "latest is $Version"
}

# GoReleaser names an archive with the tag's leading `v` stripped, and the
# binary reports the same stripped form. scripts/check-release-artifacts.py
# pins the shape, because this name is an interface: install.sh, the Homebrew
# formula and the Scoop manifest all reconstruct it.
$number = $Version -replace '^v', ''
$archive = "spill-guard_${number}_windows_${goarch}.zip"

if ($Rehearse) {
    $base = $Rehearse.TrimEnd('/')
} else {
    $base = "https://github.com/$Repo/releases/download/$Version"
}

if (-not $Dir) {
    if (-not $env:LOCALAPPDATA) {
        Die 'LOCALAPPDATA is not set, so there is no default install directory. Pass -Dir.'
    }
    $Dir = Join-Path $env:LOCALAPPDATA 'spill-guard\bin'
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('spill-guard-install-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null

try {
    function Fetch([string]$name) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile (Join-Path $work $name)
        } catch {
            Die "could not download $base/$name ($($_.Exception.Message))"
        }
    }

    Say "downloading $archive"
    Fetch $archive
    Fetch 'checksums.txt'

    $archivePath = Join-Path $work $archive
    $actual = (Get-FileHash -Algorithm SHA256 -Path $archivePath).Hash.ToLowerInvariant()

    # `<digest>  <name>`, as sha256sum writes it and as
    # scripts/check-release-artifacts.py reads it.
    $expected = ''
    foreach ($line in Get-Content (Join-Path $work 'checksums.txt')) {
        $parts = $line -split '\s+', 2
        if ($parts.Length -eq 2 -and $parts[1].Trim() -eq $archive) {
            $expected = $parts[0].Trim().ToLowerInvariant()
        }
    }

    # An empty $expected has to fail loudest, because it is what a checksums.txt
    # for some other release looks like and it is the reading a comparison
    # written the other way round would pass.
    if (-not $expected) {
        Die "checksums.txt does not list $archive, so there is nothing here to check this download against. Nothing was installed."
    }
    if ($actual -ne $expected) {
        Die "$archive does not match checksums.txt: it should be $expected and it is $actual. Nothing was installed."
    }
    Say 'sha256 matches checksums.txt'

    if ($Rehearse) {
        [Console]::Error.WriteLine('install.ps1: REHEARSAL -- the signature was NOT verified. These artifacts')
        [Console]::Error.WriteLine("install.ps1: came from $base, which is not a release, so there is no")
        [Console]::Error.WriteLine('install.ps1: provenance to check. The sha256 above answers corruption and')
        [Console]::Error.WriteLine('install.ps1: not authenticity. Do not use this to install.')
    } else {
        $found = Get-Verifier
        if ($found -eq 'cosign') {
            Fetch 'checksums.txt.sig'
            Fetch 'checksums.txt.pem'
            # The identity is pinned to this repository's release workflow at
            # this tag. A signature minted from a branch, from another
            # workflow, or from a fork is a valid Sigstore signature that this
            # has to reject.
            & cosign verify-blob `
                --certificate (Join-Path $work 'checksums.txt.pem') `
                --signature (Join-Path $work 'checksums.txt.sig') `
                --certificate-identity "https://github.com/$Repo/$Workflow@refs/tags/$Version" `
                --certificate-oidc-issuer $OidcIssuer `
                (Join-Path $work 'checksums.txt')
            if ($LASTEXITCODE -ne 0) {
                Die "cosign could not verify that checksums.txt was signed by $Repo's release workflow at $Version. Nothing was installed."
            }
            Say "cosign verified checksums.txt against $Repo at $Version"
        } elseif ($found -eq 'gh') {
            & gh attestation verify $archivePath --repo $Repo --signer-workflow "$Repo/$Workflow"
            if ($LASTEXITCODE -ne 0) {
                Die "gh could not verify that $archive was built by $Repo's release workflow. Nothing was installed."
            }
            Say "gh verified the build provenance of $archive"
        } else {
            Die "$NoVerifier Nothing was installed."
        }
    }

    Expand-Archive -Path $archivePath -DestinationPath (Join-Path $work 'unpacked') -Force
    $binary = Join-Path $work 'unpacked\spill-guard.exe'
    if (-not (Test-Path $binary)) {
        Die "$archive does not carry a spill-guard.exe at its root."
    }

    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    $installed = Join-Path $Dir 'spill-guard.exe'
    Copy-Item -Path $binary -Destination $installed -Force

    # Running it is the last assertion and the only one about this machine: a
    # cross-compiled binary for the wrong architecture verifies perfectly and
    # does not execute.
    $reported = & $installed version
    if ($LASTEXITCODE -ne 0) {
        Die "$installed was installed and does not run on this machine."
    }
    Say "installed spill-guard $reported to $installed"
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

if (($env:PATH -split ';') -notcontains $Dir) {
    Say "$Dir is not on your PATH. The hook launcher looks there anyway, so"
    Say 'spill-guard will run as a hook; add it to PATH to use the command'
    Say "yourself:    setx PATH `"%PATH%;$Dir`""
}
