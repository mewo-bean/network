package resolver

import "math/rand"

var rootServers = []string{
	"198.41.0.4:53",     // a.root-servers.net
	"199.9.14.201:53",   // b.root-servers.net
	"192.33.4.12:53",    // c.root-servers.net
	"199.7.91.13:53",    // tld-c.isc.org (d)
	"192.203.230.10:53", // e.root-servers.net
}

func GetRootServers() []string {
	servers := make([]string, len(rootServers))
	copy(servers, rootServers)

	rand.Shuffle(len(servers), func(i, j int) {
		servers[i], servers[j] = servers[j], servers[i]
	})
	return servers
}
