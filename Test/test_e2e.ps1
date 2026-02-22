$ErrorActionPreference = "Stop"

taskkill /IM seacore.exe /F 2>$null
Start-Sleep -Seconds 2

$env:RUST_LOG="info"

Write-Output "Starting Server..."
Start-Process -FilePath ".\seacore.exe" -ArgumentList "server","--config","server.json" -NoNewWindow
Start-Sleep -Seconds 2

Write-Output "Starting Client..."
Start-Process -FilePath ".\seacore.exe" -ArgumentList "client","--config","client.json" -NoNewWindow
Start-Sleep -Seconds 4

Write-Output "=== TCP PROXY TEST ==="
curl -x socks5h://127.0.0.1:10800 -I https://www.baidu.com --connect-timeout 10 2>&1

Write-Output "`n=== UDP PROXY TEST ==="
python test_udp_proxy.py 2>&1

Start-Sleep -Seconds 10
Write-Output "=== Test completed ==="
