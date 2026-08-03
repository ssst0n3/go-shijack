package main

import (
	"context"
	"fmt"
	"github.com/ssst0n3/go-shijack"
	"github.com/urfave/cli/v2"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

const (
	name  = "go-shijack"
	usage = `tcp/udp connection hijacker, go rewrite of shijack`
)

func main() {
	app := &cli.App{
		Name:  name,
		Usage: usage,
		Action: func(c *cli.Context) (err error) {
			interfaceName := c.String("interface")
			srcIp := c.String("ip")
			srcPort := c.Uint("port")
			payloadFile := c.String("payload-file")
			keep := c.Bool("keep")
			protocol := c.String("protocol")

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			switch protocol {
			case "tcp", "":
				if payloadFile == "" {
					return fmt.Errorf("tcp hijack requires --payload-file (-f)")
				}
				err = gohijack.Hijack(ctx, interfaceName, srcIp, uint32(srcPort), payloadFile, !keep)
			case "dns":
				var answerIp net.IP
				dnsDomain := c.String("dns-domain")
				dnsIp := c.String("dns-ip")
				if dnsIp != "" {
					answerIp = net.ParseIP(dnsIp)
				}
				err = gohijack.HijackDNS(ctx, interfaceName, srcIp, uint32(srcPort), dnsDomain, answerIp, payloadFile, !keep)
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
