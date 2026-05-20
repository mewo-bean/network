This repository is dedicated to the implementation of two networking tools: a DNS Server and a Port Scanner. Currently, the DNS Server is under active development.

## DNS Server (`/dns_server`)

A simple iterative DNS server built in Go. It listens for UDP queries on `127.0.0.1:5300`, parses incoming DNS packets, and performs name resolution using an iterative approach.

### Features
- **Iterative Resolution:** Resolves queries iteratively rather than recursively.
- **Custom Packet Parsing:** Includes its own logic for parsing and building DNS packets.
- **Resource Record Support:** Handles multiple record types (A, AAAA, NS, etc.).

### Project Structure
- `main.go`: Entry point to start the UDP listener and handle queries.
- `packet_builder/`: Logic for parsing and serializing DNS packets.
- `resolver/`: Core iterative resolution algorithm.
- `resource_records/`: Data structures for various DNS resource records.

### Usage

To run the DNS server locally:

```bash
cd dns_server
go run main.go
```

*Note: The Port Scanner module is yet to be implemented.*
