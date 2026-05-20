package resolver

import (
	pb "dns_server/packet_builder"
	rr "dns_server/resource_records"
	"fmt"
	"math/rand"
	"net"
	"time"
)

func sendQuery(serverAddr string, packet pb.DNSPacket) (pb.DNSPacket, error) {
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return pb.DNSPacket{}, fmt.Errorf("failed to listen on packet conn: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	raddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return pb.DNSPacket{}, fmt.Errorf("failed to resolve remote addr: %w", err)
	}

	queryBytes, err := packet.SerializeDNS()
	if err != nil {
		return pb.DNSPacket{}, err
	}

	if _, err := conn.WriteTo(queryBytes, raddr); err != nil {
		return pb.DNSPacket{}, fmt.Errorf("failed to write to remote: %w", err)
	}

	responseBytes := make([]byte, 512)
	n, addr, err := conn.ReadFrom(responseBytes)
	if err != nil {
		return pb.DNSPacket{}, err
	}

	if !addr.(*net.UDPAddr).IP.Equal(raddr.IP) {
		return pb.DNSPacket{}, fmt.Errorf("received packet from unexpected IP: %s", addr)
	}

	return pb.ParsePacket(responseBytes[:n])
}

func buildQuery(name []byte, qtype rr.RecordType) pb.DNSPacket {
	hdr := pb.DNSHeader{
		ID:      uint16(rand.Intn(65535)),
		QDCount: 1,
	}
	hdr.SetOpCode(pb.OpCodeQuery)
	hdr.SetRecursionDesired(false)

	q := pb.DNSQuestion{
		Name:  name,
		Type:  qtype,
		Class: 1,
	}

	return pb.DNSPacket{
		Header:    hdr,
		Questions: []pb.DNSQuestion{q},
	}
}
