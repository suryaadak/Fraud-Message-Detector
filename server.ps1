# Phishing Detection Platform - Robust Local HTTP Server
# Uses System.Net.Sockets.TcpListener (Works on any Windows environment)
# Run with: powershell -ExecutionPolicy Bypass -File server.ps1

$port = 8080
$rootPath = $PSScriptRoot
if (-not $rootPath) {
    $rootPath = (Get-Location).Path
}

$localAddress = [System.Net.IPAddress]::Loopback
$listener = New-Object System.Net.Sockets.TcpListener($localAddress, $port)

try {
    $listener.Start()
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host " [PHISHSHIELD] Phishing Detection Platform Server" -ForegroundColor Green
    Write-Host " Local Web Server running at: http://127.0.0.1:$port/" -ForegroundColor Yellow
    Write-Host " Press Ctrl+C in this console window to stop the server" -ForegroundColor Gray
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""

    # Open browser automatically if not in a headless session
    Start-Process "http://127.0.0.1:$port/" -ErrorAction SilentlyContinue

    while ($true) {
        $client = $listener.AcceptTcpClient()
        $stream = $client.GetStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.BinaryWriter($stream)

        $requestLine = $reader.ReadLine()
        if (-not $requestLine) {
            $client.Close()
            continue
        }

        # Example requestLine: GET /index.html HTTP/1.1
        $tokens = $requestLine.Split(' ')
        $method = $tokens[0]
        $urlPath = if ($tokens.Count -ge 2) { $tokens[1] } else { "/" }

        # Strip query string and decode URL safely
        if ($urlPath.Contains('?')) {
            $urlPath = $urlPath.Substring(0, $urlPath.IndexOf('?'))
        }
        
        try {
            $urlPath = [System.Uri]::UnescapeDataString($urlPath).TrimStart('/')
        } catch {
            $urlPath = $urlPath.TrimStart('/')
        }

        if ([string]::IsNullOrEmpty($urlPath)) {
            $urlPath = "index.html"
        }

        # Resolve clean file path safely
        $targetFile = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($rootPath, $urlPath))
        
        # Security check - ensure path stays inside project directory
        if (-not $targetFile.StartsWith($rootPath)) {
            $header = "HTTP/1.1 403 Forbidden`r`nContent-Length: 9`r`nConnection: close`r`n`r`nForbidden"
            $writer.Write([System.Text.Encoding]::ASCII.GetBytes($header))
            $writer.Flush()
            $client.Close()
            continue
        }

        if (Test-Path $targetFile -PathType Leaf) {
            $ext = [System.IO.Path]::GetExtension($targetFile).ToLower()
            $mimeType = switch ($ext) {
                ".html" { "text/html; charset=utf-8" }
                ".css"  { "text/css; charset=utf-8" }
                ".js"   { "application/javascript; charset=utf-8" }
                ".json" { "application/json; charset=utf-8" }
                ".svg"  { "image/svg+xml" }
                ".png"  { "image/png" }
                ".jpg"  { "image/jpeg" }
                ".ico"  { "image/x-icon" }
                default { "application/octet-stream" }
            }

            $bytes = [System.IO.File]::ReadAllBytes($targetFile)
            $header = "HTTP/1.1 200 OK`r`nContent-Type: $mimeType`r`nContent-Length: $($bytes.Length)`r`nAccess-Control-Allow-Origin: *`r`nConnection: close`r`n`r`n"
            $writer.Write([System.Text.Encoding]::ASCII.GetBytes($header))
            $writer.Write($bytes)
            $writer.Flush()
        } else {
            $msg = "404 Not Found"
            $header = "HTTP/1.1 404 Not Found`r`nContent-Type: text/plain`r`nContent-Length: $($msg.Length)`r`nConnection: close`r`n`r`n$msg"
            $writer.Write([System.Text.Encoding]::ASCII.GetBytes($header))
            $writer.Flush()
        }

        $client.Close()
    }
}
catch {
    Write-Host "Server Exception: $_" -ForegroundColor Red
}
finally {
    if ($listener) {
        $listener.Stop()
    }
}
