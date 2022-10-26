package gohijack

import (
	"math/big"
	"net"
)

func inetAtoN_(ip string) *big.Int {
	return big.NewInt(0).SetBytes(net.ParseIP(ip).To4())
}

func InetAtoNtoBytes(ip string) []byte {
	return inetAtoN_(ip).Bytes()
}

func InetAtoN(ip string) int64 {
	return inetAtoN_(ip).Int64()
}
