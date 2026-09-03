# Barbarika Live Demo - Attack Simulation Script
# Appends attack log signatures into mock logs using shared I/O to demonstrate real-time ingestion

$authLog = (Get-Item ".\mock_logs\auth.log").FullName
$nginxLog = (Get-Item ".\mock_logs\nginx_access.log").FullName

Write-Host "==================================================================" -ForegroundColor Red
Write-Host "       BARBARIKA ATTACK SIMULATION INJECTOR (Category III & X)    " -ForegroundColor Red
Write-Host "==================================================================" -ForegroundColor Red

function Append-LogLine {
    param ([string]$Path, [string]$Text)
    [System.IO.File]::AppendAllText($Path, "$Text`n")
}

Start-Sleep -Seconds 1

Write-Host "`n[Attack 1] Simulating SSH Brute-Force Attack (Category III)..." -ForegroundColor Yellow
Append-LogLine -Path $authLog -Text "Aug 19 10:15:01 primary-srv-01 sshd[9901]: Failed password for root from 185.220.101.4 port 41001 ssh2"
Start-Sleep -Milliseconds 300
Append-LogLine -Path $authLog -Text "Aug 19 10:15:02 primary-srv-01 sshd[9902]: Failed password for root from 185.220.101.4 port 41002 ssh2"
Start-Sleep -Milliseconds 300
Append-LogLine -Path $authLog -Text "Aug 19 10:15:03 primary-srv-01 sshd[9903]: Failed password for root from 185.220.101.4 port 41003 ssh2"
Start-Sleep -Milliseconds 300
Append-LogLine -Path $authLog -Text "Aug 19 10:15:05 primary-srv-01 sshd[9904]: Accepted password for ubuntu from 185.220.101.4 port 41004 ssh2"
Start-Sleep -Milliseconds 300
Append-LogLine -Path $authLog -Text "Aug 19 10:15:06 primary-srv-01 sudo:   ubuntu : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"

Write-Host "[Attack 1 Complete] SSH Privilege Escalation Logs Injected." -ForegroundColor Green

Start-Sleep -Seconds 1

Write-Host "`n[Attack 2] Simulating Web Exploitation & SQL Injection (Category X)..." -ForegroundColor Yellow
Append-LogLine -Path $nginxLog -Text '185.220.101.4 - - [19/Aug/2026:10:16:01 +0000] "GET /.git/config HTTP/1.1" 404 162 "-" "sqlmap/1.6"'
Start-Sleep -Milliseconds 300
Append-LogLine -Path $nginxLog -Text '185.220.101.4 - - [19/Aug/2026:10:16:03 +0000] "GET /api/v1/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 512 "-" "sqlmap/1.6"'

Write-Host "[Attack 2 Complete] Nginx Exploitation Logs Injected." -ForegroundColor Green
Write-Host "`nCheck your Go Daemon terminal window to observe real-time tailing, hashing & signing!" -ForegroundColor Cyan
