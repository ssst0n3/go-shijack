package main

import (
	"fmt"
	"github.com/ssst0n3/go-shijack"
	"github.com/urfave/cli/v2"
	"log"
	"net"
	"os"
)

const (
	name  = "go-shijack"
	usage = `tcp/udp connection hijacker, go rewrite of shijack`
)

func main() {
	app := &cli.App{
		Name:  name,
		Usage: usage,
		Action: func(context *cli.Context) (err error) {
			interfaceName := context.String("interface")
			srcIp := context.String("ip")
			srcPort := context.Uint("port")
			payloadFile := context.String("payload-file")
			keep := context.Bool("keep")
			protocol := context.String("protocol")
			switch protocol {
			case "tcp", "":
				if payloadFile == "" {
					return fmt.Errorf("tcp hijack requires --payload-file (-f)")
				}
				gohijack.Hijack(interfaceName, srcIp, uint32(srcPort), payloadFile, !keep)
			case "dns":
				var answerIp net.IP
				dnsDomain := context.String("dns-domain")
				dnsIp := context.String("dns-ip")
				if dnsIp != "" {
					answerIp = net.ParseIP(dnsIp)
				}
				gohijack.HijackDNS(interfaceName, srcIp, uint32(srcPort), dnsDomain, answerIp, payloadFile, !keep)
			default:
				log.Fatalf("unknown protocol: %s (want tcp or dns)", protocol)
			}
			return
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "interface",
				Aliases:  []string{"t"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "ip",
				Aliases:  []string{"i"},
				Required: true,
			},
			&cli.UintFlag{
				Name:     "port",
				Aliases:  []string{"p"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "payload-file",
				Aliases:  []string{"f"},
				Required: false,
			},
			&cli.BoolFlag{
				Name:    "keep",
				Aliases: []string{"k"},
			},
			&cli.StringFlag{
				Name:    "protocol",
				Aliases: []string{"proto"},
				Value:   "tcp",
				Usage:   "tcp or dns",
			},
			&cli.StringFlag{
				Name:    "dns-domain",
				Usage:   "dns hijack: domain to answer (auto-construct mode)",
			},
			&cli.StringFlag{
				Name:    "dns-ip",
				Usage:   "dns hijack: A record IP to return (auto-construct mode)",
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
