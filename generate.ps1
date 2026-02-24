$base = "https://stats-games.com"

for ($i = 1; $i -le 100; $i++) {
    $guid = [guid]::NewGuid().ToString()

    $payload = @{
        name  = "Player_$i"
        tag   = (1000 + $i).ToString()
        score = 100000 - ($i * 731)
    }

    $json = $payload | ConvertTo-Json -Compress

    Invoke-RestMethod `
        -Method Post `
        -Uri "$base/leaderboard/$guid" `
        -ContentType "application/json; charset=utf-8" `
        -Body $json | Out-Null

    Start-Sleep -Milliseconds 40
}

"Done"