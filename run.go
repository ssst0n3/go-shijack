package gohijack

import "github.com/ssst0n3/awesome_libs/log"

func Run(src, dst string, seq, ack uint32, reset bool) {
	log.Logger.Infof("Using SEQ = 0x{%x}, ACK = 0x{%x}", seq, ack)
	//connection := NewConnection(src, dst, seq, ack)
	//if reset {
	//	connection.Reset()
	//	log.Logger.Info("Connection has been reset")
	//}
}
