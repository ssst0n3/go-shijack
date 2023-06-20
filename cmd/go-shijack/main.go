package main

import (
	"github.com/ssst0n3/go-shijack"
	"github.com/urfave/cli/v2"
	"log"
	"os"
)

const (
	name  = "go-shijack"
	usage = `tcp connection hijacker, go rewrite of shijack`
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
			gohijack.Hijack(interfaceName, srcIp, uint32(srcPort), dstIp, dstPort, payloadFile, !keep)
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
				Required: true,
			},
			&cli.BoolFlag{
				Name:    "keep",
				Aliases: []string{"k"},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
