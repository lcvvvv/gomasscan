package scanner

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ipranger"
	"github.com/projectdiscovery/networkpolicy"
)

// PkgFlag represent the TCP packet flag
type PkgFlag int

const (
	SYN PkgFlag = iota
	ACK
)

type Scanner struct {
	//发包源IP
	sourceIP net.IP
	//发包源网卡
	networkInterface *net.Interface
	//发包源端口
	listenPort int
	//目的IP，地址范围，便于处理返回数据包
	ipRanger *ipranger.IPRanger
	//监听网卡组
	handlers Handlers
	//端口扫描成功结果发送信道
	tcpResultChan chan *PkgResult
	//发包相关
	tcpSequencer      *TCPSequencer
	tcpPacketListener net.PacketConn
	tcpPacketSend     chan *PkgSend
	serializeOptions  gopacket.SerializeOptions
	//结束标识符
	done        bool
	HandlerOpen func(ip string, port int)

	//retries           int
	//rate              int
	//timeout           time.Duration
	//icmpPacketListener net.PacketConn
	//proxyDialer        proxy.Dialer
	//Ports    []int
	//icmpChan       chan *PkgResult
	//icmpPacketSend chan *PkgSend
}

// PkgSend is a TCP package
type PkgSend struct {
	ip       string
	port     int
	flag     PkgFlag
	SourceIP string
}

// PkgResult contains the results of sending TCP packages
type PkgResult struct {
	ip   string
	port int
}

var (
	newScannerCallback        func(s *Scanner) error
	setupHandlerCallback      func(s *Scanner, interfaceName string) error
	tcpReadWorkerPCAPCallback func(s *Scanner)
	cleanupHandlersCallback   func(s *Scanner)
)

const (
	maxRetries     = 10
	sendDelayMsec  = 10
	chanSize       = 1000
	packetSendSize = 2500
	snapLength     = 65536
	readTimeout    = 1500
)

// NewScanner creates a new full port scanner that scans all ports using SYN packets.
func NewScanner() (*Scanner, error) {
	rand.Seed(time.Now().UnixNano())

	iprang, err := ipranger.New()
	if err != nil {
		return nil, err
	}

	var nPolicyOptions networkpolicy.Options
	//黑名单
	//nPolicyOptions.DenyList = append(nPolicyOptions.DenyList, options.ExcludedIps...)
	nPolicy, err := networkpolicy.New(nPolicyOptions)
	if err != nil {
		return nil, err
	}
	iprang.Np = nPolicy

	scanner := &Scanner{
		serializeOptions: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},

		tcpSequencer: NewTCPSequencer(),
		ipRanger:     iprang,
		HandlerOpen:  func(ip string, port int) {},

		//timeout:      time.Second * 3,
		//retries:      3,
		//rate:         1024,
	}

	if newScannerCallback != nil {
		if err := newScannerCallback(scanner); err != nil {
			return nil, err
		}
	}

	return scanner, nil
}

// Done the scanner and terminate all workers
func (s *Scanner) Done() {
	s.cleanupHandlers()
	s.tcpPacketListener.Close()
	s.done = true
}

// Add the scanner and add ip filter in ipRanger
func (s *Scanner) Add(host string) error {
	return s.ipRanger.Add(host)
}

// startWorkers of the scanner
func (s *Scanner) startWorkers() {
	go s.tcpReadWorker()
	go s.tcpReadWorkerPCAP()
	go s.tcpWriteWorker()
	go s.tcpResultWorker()
}

// tcpWriteWorker that sends out TCP packets
func (s *Scanner) tcpWriteWorker() {
	for pkg := range s.tcpPacketSend {
		s.sendAsyncPkg(pkg.ip, pkg.port, pkg.flag)
	}
}

//sendAsyncPkg sends a single packet to a port
func (s *Scanner) sendAsyncPkg(ip string, port int, pkgFlag PkgFlag) {
	// Construct all the network layers we need.
	ip4 := layers.IPv4{
		SrcIP:    s.sourceIP,
		DstIP:    net.ParseIP(ip),
		Version:  4,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
	}
	tcpOption := layers.TCPOption{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xB4},
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.listenPort),
		DstPort: layers.TCPPort(port),
		Window:  1024,
		Seq:     s.tcpSequencer.Next(),
		Options: []layers.TCPOption{tcpOption},
	}

	if pkgFlag == SYN {
		tcp.SYN = true
	} else if pkgFlag == ACK {
		tcp.ACK = true
	}

	err := tcp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		gologger.Debug().Msgf("Can not set network layer for %s:%d port: %s\n", ip, port, err)
	} else {
		err = s.send(ip, s.tcpPacketListener, &tcp)
		if err != nil {
			gologger.Debug().Msgf("Can not send packet to %s:%d port: %s\n", ip, port, err)
		}
	}
}

// send sends the given layers as a single packet on the network.
func (s *Scanner) send(destIP string, conn net.PacketConn, l ...gopacket.SerializableLayer) error {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.serializeOptions, l...); err != nil {
		return err
	}

	var (
		retries int
		err     error
	)

send:
	if retries >= maxRetries {
		return err
	}
	_, err = conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP(destIP)})
	if err != nil {
		retries++
		// introduce a small delay to allow the network interface to flush the queue
		time.Sleep(time.Duration(sendDelayMsec) * time.Millisecond)
		goto send
	}
	return err
}

// tcpReadWorker reads and parse incoming TCP packets
func (s *Scanner) tcpReadWorker() {
	defer s.tcpPacketListener.Close()
	data := make([]byte, 4096)
	for {
		if s.done == true {
			break
		}
		// nolint:errcheck // just empty the buffer
		s.tcpPacketListener.ReadFrom(data)
	}
}

// tcpReadWorkerPCAP reads and parse incoming TCP packets with pcap
func (s *Scanner) tcpReadWorkerPCAP() {
	if tcpReadWorkerPCAPCallback != nil {
		tcpReadWorkerPCAPCallback(s)
	}
}

// tcpResultWorker handles probes and scan results
// 输出处理函数
func (s *Scanner) tcpResultWorker() {
	for ip := range s.tcpResultChan {
		s.HandlerOpen(ip.ip, ip.port)
	}
}

// SendSYN outgoing TCP packets
func (s *Scanner) SendSYN(ip string, port int, pkgtype PkgFlag) {
	s.tcpPacketSend <- &PkgSend{
		ip:   ip,
		port: port,
		flag: pkgtype,
	}
}

func (s *Scanner) Init() error {
	err := s.initSource(DefaultExternalTargetForGetSource)
	if err != nil {
		return err
	}
	err = s.listen()
	if err != nil {
		return err
	}
	//启动相关函数
	s.startWorkers()
	return nil
}

// listen to listen on all interfaces
func (s *Scanner) listen() error {
	if s.networkInterface != nil {
		return s.listenInterface(s.networkInterface.Name)
	}
	itfs, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, itf := range itfs {
		if itf.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if err := s.listenInterface(itf.Name); err != nil {
			gologger.Warning().Msgf("Error on interface %s: %s", itf.Name, err)
		}
	}

	return nil
}

// listenInterface to listen on the specified interface
func (s *Scanner) listenInterface(interfaceName string) error {
	if setupHandlerCallback != nil {
		return setupHandlerCallback(s, interfaceName)
	}

	return nil
}

// cleanupHandlers for all interfaces
func (s *Scanner) cleanupHandlers() {
	if cleanupHandlersCallback != nil {
		cleanupHandlersCallback(s)
	}
}

var DefaultExternalTargetForGetSource = "8.8.8.8"

// initSource automatically with ip and interface
func (s *Scanner) initSource(ip string) error {
	var err error
	s.sourceIP, s.networkInterface, err = getSrcParameters(ip)
	if err != nil {
		return err
	}

	return nil
}

// getSrcParameters gets the network parameters from the destination ip
func getSrcParameters(destIP string) (srcIP net.IP, networkInterface *net.Interface, err error) {
	srcIP, err = getSourceIP(net.ParseIP(destIP))
	if err != nil {
		return
	}
	networkInterface, err = getInterfaceFromIP(srcIP)
	if err != nil {
		return
	}
	return
}

// getSourceIP gets the local ip based on our destination ip
func getSourceIP(dstip net.IP) (net.IP, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		return nil, err
	}

	con, dialUpErr := net.DialUDP("udp", nil, serverAddr)
	if dialUpErr != nil {
		return nil, dialUpErr
	}

	defer con.Close()
	if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
		return udpaddr.IP, nil
	}

	return nil, nil
}

// getInterfaceFromIP gets the name of the network interface from local ip address
func getInterfaceFromIP(ip net.IP) (*net.Interface, error) {
	address := ip.String()

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, i := range interfaces {
		byNameInterface, err := net.InterfaceByName(i.Name)
		if err != nil {
			return nil, err
		}

		addresses, err := byNameInterface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, v := range addresses {
			// Check if the IP for the current interface is our
			// source IP. If yes, return the interface
			if strings.HasPrefix(v.String(), address+"/") {
				return byNameInterface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface found for ip %s", address)
}

// ICMPReadWorker reads packets from the network layer
//func (s *Scanner) ICMPReadWorker() {
//	defer s.icmpPacketListener.Close()
//	data := make([]byte, 1500)
//	for {
//		if s.State == done {
//			break
//		}
//		n, addr, err := s.icmpPacketListener.ReadFrom(data)
//		if err != nil {
//			continue
//		}
//
//		if s.State == Guard {
//			continue
//		}
//
//		rm, err := icmp.ParseMessage(ProtocolICMP, data[:n])
//		if err != nil {
//			continue
//		}
//
//		switch rm.Type {
//		case ipv4.ICMPTypeEchoReply, ipv4.ICMPTypeTimestamp:
//			s.icmpChan <- &PkgResult{ip: addr.String()}
//		}
//	}
//}

//// ConnectPort a single host and port
//func (s *Scanner) ConnectPort(host string, port int, timeout time.Duration) (bool, error) {
//	hostport := net.JoinHostPort(host, fmt.Sprint(port))
//	var (
//		err  error
//		conn net.Conn
//	)
//	if s.proxyDialer != nil {
//		conn, err = s.proxyDialer.Dial("tcp", hostport)
//		if err != nil {
//			return false, err
//		}
//	} else {
//		conn, err = net.DialTimeout("tcp", hostport, timeout)
//	}
//	if err != nil {
//		return false, err
//	}
//	conn.Close()
//	return true, err
//}

// ScanSyn a target ip
//func (s *Scanner) ScanSyn(ip string) {
//	for _, port := range s.Ports {
//		s.SendSYN(ip, port, SYN)
//	}
//}

// ACKPort sends an ACK packet to a port
//func (s *Scanner) ACKPort(dstIP string, port int, timeout time.Duration) (bool, error) {
//	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
//	if err != nil {
//		return false, err
//	}
//	defer conn.Close()
//
//	rawPort, err := freeport.GetFreePort()
//	if err != nil {
//		return false, err
//	}
//
//	// Construct all the network layers we need.
//	ip4 := layers.IPv4{
//		SrcIP:    s.sourceIP,
//		DstIP:    net.ParseIP(dstIP),
//		Version:  4,
//		TTL:      255,
//		Protocol: layers.IPProtocolTCP,
//	}
//	tcpOption := layers.TCPOption{
//		OptionType:   layers.TCPOptionKindMSS,
//		OptionLength: 4,
//		OptionData:   []byte{0x12, 0x34},
//	}
//
//	tcp := layers.TCP{
//		SrcPort: layers.TCPPort(rawPort),
//		DstPort: layers.TCPPort(port),
//		ACK:     true,
//		Window:  1024,
//		Seq:     s.tcpSequencer.Next(),
//		Options: []layers.TCPOption{tcpOption},
//	}
//
//	err = tcp.SetNetworkLayerForChecksum(&ip4)
//	if err != nil {
//		return false, err
//	}
//
//	err = s.send(dstIP, conn, &tcp)
//	if err != nil {
//		return false, err
//	}
//
//	data := make([]byte, 4096)
//	for {
//		n, addr, err := conn.ReadFrom(data)
//		if err != nil {
//			break
//		}
//
//		// not matching ip
//		if addr.String() != dstIP {
//			gologger.Debug().Msgf("Discarding TCP packet from non target ip %s for %s\n", dstIP, addr.String())
//			continue
//		}
//
//		packet := gopacket.NewPacket(data[:n], layers.LayerTypeTCP, gopacket.Default)
//		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
//			tcp, ok := tcpLayer.(*layers.TCP)
//			if !ok {
//				continue
//			}
//			// We consider only incoming packets
//			if tcp.DstPort != layers.TCPPort(rawPort) {
//				gologger.Debug().Msgf("Discarding TCP packet from %s:%d not matching %s:%d port\n", addr.String(), tcp.DstPort, dstIP, rawPort)
//				continue
//			} else if tcp.RST {
//				gologger.Debug().Msgf("Accepting RST packet from %s:%d\n", addr.String(), tcp.DstPort)
//				return true, nil
//			}
//		}
//	}
//
//	return false, nil
//}

// EnqueueICMP outgoing ICMP packets
//func (s *Scanner) EnqueueICMP(ip string, pkgtype PkgFlag) {
//	s.icmpPacketSend <- &PkgSend{
//		ip:   ip,
//		flag: pkgtype,
//	}
//}

// ICMPWriteWorker writes packet to the network layer
//func (s *Scanner) ICMPWriteWorker() {
//	for pkg := range s.icmpPacketSend {
//		if pkg.flag == ICMPECHOREQUEST && pingIcmpEchoRequestAsyncCallback != nil {
//			pingIcmpEchoRequestAsyncCallback(s, pkg.ip)
//		} else if pkg.flag == ICMPTIMESTAMPREQUEST && pingIcmpTimestampRequestAsyncCallback != nil {
//			pingIcmpTimestampRequestAsyncCallback(s, pkg.ip)
//		}
//	}
//}
