$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$outputDirectory = Join-Path $projectRoot 'dist'
$archivePath = Join-Path $outputDirectory 'portal-zespolu-wariant-10.zip'

# Explicit source list: never include local databases, passwords or dependencies.
$sourceNames = @('src', 'public', 'scripts', 'test', 'package.json', 'package-lock.json', 'README.md', 'Uruchom.bat', '.gitignore', '.editorconfig')
$sources = @($sourceNames | ForEach-Object { (Resolve-Path -LiteralPath (Join-Path $projectRoot $_)).Path })
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

# ZipArchive also includes dotfiles, which Compress-Archive can omit on Windows.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$stream = [System.IO.File]::Open($archivePath, [System.IO.FileMode]::Create)
$archive = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($source in $sources) {
        $item = Get-Item -LiteralPath $source -Force
        $files = if ($item.PSIsContainer) { Get-ChildItem -LiteralPath $source -File -Recurse -Force } else { @($item) }
        foreach ($file in $files) {
            $relative = $file.FullName.Substring($projectRoot.Length + 1).Replace('\', '/')
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $relative, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
    }
} finally {
    $archive.Dispose()
    $stream.Dispose()
}
Write-Host "Gotowe: $archivePath"
