//go:build cgo

package sniff

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/ssst0n3/awesome_libs/awesome_error"
	"golang.org/x/net/bpf"
	"os"
	"time"
)

type AfPacket struct {
}

const blockForever = -time.Millisecond * 10

func newAfPacketHandle(device string, snapLen int, blockSize int, numBlocks int,
	useVLAN bool, timeout time.Duration) (handler *afpacket.TPacket, err error) {

	var opts []interface{}
	if device != "any" {
		opts = append(opts, afpacket.OptInterface(device))
	}
	defaultOpts := []interface{}{
		afpacket.OptFrameSize(snapLen),
		afpacket.OptBlockSize(blockSize),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptAddVLANHeader(useVLAN),
		afpacket.OptPollTimeout(timeout),
		afpacket.SocketRaw,
		afpacket.TPacketVersion3,
	}
	opts = append(opts, defaultOpts...)
	handler, err = afpacket.NewTPacket(opts...)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	return
}

func afPacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {

	if snaplen < pageSize {
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}

	// 128 is the default from the gopacket library so just use that
	blockSize = frameSize * 128
	numBlocks = (targetSizeMb * 1024 * 1024) / blockSize

	if numBlocks == 0 {
		return 0, 0, 0, fmt.Errorf("Interface buffersize is too small")
	}

	return frameSize, blockSize, numBlocks, nil
}

func (s AfPacket) Sniff(device string, filter []bpf.RawInstruction) (packets chan gopacket.Packet, err error) {
	snaplen := 65535
	bufferSize := 8
	addVlan := false
	frameSize, blockSize, numBlocks, err := afPacketComputeSize(bufferSize, snaplen, os.Getpagesize())
	handler, err := newAfPacketHandle(device, frameSize, blockSize, numBlocks, addVlan, blockForever)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	err = handler.SetBPF(filter)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	//source := gopacket.ZeroCopyPacketDataSource(handler)
	//defer handler.Close()

	packetSource := gopacket.NewPacketSource(handler, layers.LayerTypeEthernet)
	packets = packetSource.Packets()
	return
}
