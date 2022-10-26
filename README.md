# go-shijack

tcp connection hijacker, go rewrite of shijack from 2001.

## usage

```
root@ecs-c5a4:~# ./go-shijack -t eth0 -i 169.254.169.254 -p 80 -f flag &
[1] 362712
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