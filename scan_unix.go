//go:build linux || darwin

package gomasscan

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/phayes/freeport"
)

func init() {
	newScannerCallback = newScannerUnix
	setupHandlerCallback = setupHandlerUnix
	tcpReadWorkerPCAPCallback = tcpReadWorkerPCAPUnix
	cleanupHandlersCallback = cleanupHandlersUnix
}

type Handlers struct {
	Active   []*pcap.Handle
	Inactive []*pcap.InactiveHandle
}

func newScannerUnix(scanner *Scanner) error {
	rawPort, err := freeport.GetFreePort()
	if err != nil {
		return err
	}
	scanner.listenPort = rawPort

	tcpConn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: net.ParseIP(fmt.Sprintf("0.0.0.0:%d", rawPort))})
	if err != nil {
		return err
	}
	scanner.tcpPacketListener = tcpConn

	var handlers Handlers
	scanner.handlers = handlers

	scanner.tcpResultChan = make(chan *PkgResult, chanSize)
	scanner.tcpPacketSend = make(chan *PkgSend, packetSendSize)
	return nil
}

func setupHandlerUnix(s *Scanner, interfaceName string) error {
	inactive, err := pcap.NewInactiveHandle(interfaceName)
	if err != nil {
		return err
	}

	err = inactive.SetSnapLen(snapLength)
	if err != nil {
		return err
	}

	readTimeout := time.Duration(readTimeout) * time.Millisecond
	if err = inactive.SetTimeout(readTimeout); err != nil {
		s.cleanupHandlers()
		return err
	}
	err = inactive.SetImmediateMode(true)
	if err != nil {
		return err
	}

	handlers := s.handlers
	handlers.Inactive = append(handlers.Inactive, inactive)

	handle, err := inactive.Activate()

	if err != nil {
		s.cleanupHandlers()
		return err
	}

	handlers.Active = append(handlers.Active, handle)

	// Strict BPF filter
	// + Packets coming from target ip
	// + Destination port equals to sender socket source port
	err = handle.SetBPFFilter(fmt.Sprintf("tcp and dst port %d and tcp[13]=18", s.listenPort))

	if err != nil {
		s.cleanupHandlers()
		return err
	}

	s.handlers = handlers

	return nil
}

func tcpReadWorkerPCAPUnix(s *Scanner) {
	defer s.cleanupHandlers()

	var wgread sync.WaitGroup

	handlers := s.handlers

	for _, handler := range handlers.Active {
		wgread.Add(1)
		go func(handler *pcap.Handle) {
			defer wgread.Done()

			var (
				eth layers.Ethernet
				ip4 layers.IPv4
				tcp layers.TCP
			)

			// Interfaces with MAC (Physical + Virtualized)
			parserMac := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)
			// Interfaces without MAC (TUN/TAP)
			parserNoMac := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp)

			var parsers []*gopacket.DecodingLayerParser
			parsers = append(parsers, parserMac, parserNoMac)

			var decoded []gopacket.LayerType

			for {
				data, _, err := handler.ReadPacketData()
				if err != nil {
					if err == io.EOF {
						break
					}
					continue
				}
				for _, parser := range parsers {
					if err := parser.DecodeLayers(data, &decoded); err != nil {
						continue
					}
					for _, layerType := range decoded {
						if layerType != layers.LayerTypeTCP {
							continue
						}
						if s.ipRanger.Contains(ip4.SrcIP.String()) == false {
							//gologger.Debug().Msgf("Discarding TCP packet from non target ip %s\n", ip4.SrcIP.String())
							continue
						}
						if tcp.DstPort != layers.TCPPort(s.listenPort) {
							continue
						}
						// We consider only incoming packets
						if tcp.ACK == false || tcp.SYN == false {
							continue
						}
						s.tcpResultChan <- &PkgResult{ip: ip4.SrcIP.String(), port: int(tcp.SrcPort)}
					}
				}
			}
		}(handler)
	}

	wgread.Wait()
}

// cleanupHandlers for all interfaces
func cleanupHandlersUnix(s *Scanner) {
	handler := s.handlers
	for _, handler := range handler.Active {
		handler.Close()
	}
	for _, inactiveHandler := range handler.Inactive {
		inactiveHandler.CleanUp()
	}
}
