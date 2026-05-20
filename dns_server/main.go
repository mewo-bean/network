package main

import (
	pb "dns_server/packet_builder"
	rs "dns_server/resolver"
	"log"
	"net"
)

func main() {
	log.Println("Starting iterative DNS server on :5300...")

	addr := net.UDPAddr{
		Port: 5300,
		IP:   net.ParseIP("127.0.0.1"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}
	defer conn.Close()

	resolver := rs.NewResolver()

	for {
		buf := make([]byte, 512)
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading from UDP: %v", err)
			continue
		}

		go handleQuery(resolver, conn, clientAddr, buf[:n])
	}
}

func handleQuery(resolver *rs.Resolver, conn *net.UDPConn, clientAddr *net.UDPAddr, requestBytes []byte) {
	log.Printf("Received query from %s", clientAddr)

	requestPacket, err := pb.ParsePacket(requestBytes)
	if err != nil {
		log.Printf("Error parsing packet: %v", err)
		return
	}

	responsePacket := resolver.Resolve(requestPacket)

	responseBytes, err := responsePacket.SerializeDNS()
	if err != nil {
		log.Printf("Error serializing response: %v", err)
		return
	}

	if _, err := conn.WriteToUDP(responseBytes, clientAddr); err != nil {
		log.Printf("Error writing response to %s: %v", clientAddr, err)
	}
}
