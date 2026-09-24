# BjlDns
 The DNS project provides everything you need to run a DNS server and  a DNS client
 and a NsLookup tool.

The intent of this DNS code is to support a large number of domains with very little administrative overhead.
 
 this is one of the eldest packages in the library adn I think it's due for an upgrade...
 
# Major Features:
 +  Supports unique configuration for any domain.
 +  Supports a common configuration that will be used for any domain that does not have a unique configuration.
 +  Domains may be in a database or file system
 +  Support Dynamic DNS (DDNS) with trivial configuration
   
 
Dependencies:  
+ BjlCore  
+ BjlIo
 			

# Running in production

Run the server under a supervisor (systemd, launchd, a container runtime) that restarts it when it stops, and let the JVM exit on fatal errors instead of limping on:

```
java -Xmx256m -XX:+ExitOnOutOfMemoryError \
     -DJDns.properties=/data/services/dns/config/JDns.properties \
     -cp bjl_dns.jar:bjl_core.jar:bjl_io.jar us.bringardner.net.dns.server.DnsServer
```

`DnsServer.main` also installs `FatalErrorHandler`: any thread that dies from an uncaught error is logged, and on a JVM error (e.g. `OutOfMemoryError`) the process halts with exit code 1 so the supervisor starts a clean one. Set `-DJDns.exitOnFatalError=false` to only log. Applications that embed the server can call `FatalErrorHandler.install(true)`.

Example systemd unit:

```
[Unit]
Description=BjlDns
After=network-online.target

[Service]
ExecStart=/usr/bin/java -Xmx256m -XX:+ExitOnOutOfMemoryError -DJDns.properties=/data/services/dns/config/JDns.properties -cp /opt/bjldns/lib/* us.bringardner.net.dns.server.DnsServer
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

## Configuration properties

Set in the properties file (`JDns.properties`) or with `-D`. Besides the existing ones (`JDns.dnsPort`, `JDns.bindAddress`, `JDns.zone.dir`, `JDns.master.zone`, ...):

A bind address of `localhost` means this host's own name (its network address), not the loopback interface, so the server is reachable from the network; a warning is logged. Use `127.0.0.1` to listen on loopback only.

| Property | Default | Meaning |
|---|---|---|
| `JDns.udpTimeout` / `JDns.tcpTimeout` | `JDns.timeout` (5000) | Socket timeouts (ms); how often listeners check for shutdown |
| `JDns.tcpBindAddress` / `JDns.udp.bindAddress` | `JDns.bindAddress` | Per-protocol listen address |
| `JDns.udpMaxResponse` | 512 | Largest UDP response (bytes) to clients without EDNS; bigger answers are truncated (TC) and clients retry over TCP |
| `JDns.ednsUdpSize` | 1232 | Largest UDP response to EDNS clients (512–4096; the client's own size is used if smaller). Responses echo an OPT record; EDNS versions other than 0 get BADVERS |
| `JDns.tcpMaxConnections` | 64 | TCP connections served at once; more are closed immediately |
| `JDns.tcpIdleTimeout` | 10000 | An idle TCP connection is closed after this many ms |
| `JDns.maxCacheEntries` | 10000 | Resolver cache size (LRU) |
| `JDns.cacheSweepSeconds` | 60 | How often expired cache entries are removed |
| `JDns.maxCacheAge` | 1800000 | Upper bound (ms) on how long anything is cached |
| `JDns.maxNegativeTtl` | 10800 | Upper bound (s) for caching "does not exist" answers |
| `JDns.maxDelegations` | 10000 | Learned delegations kept (LRU) |
| `JDns.delegationMaxAge` | 3600 | Seconds a learned delegation is used before a fresh referral replaces it |
| `Resolver.maxBacklog` | 200 | Queued recursive queries; when full, clients get SERVFAIL (a CNAME answer is sent without the target's records). Logged at most every 10 s |
| `TCPProcCount` | 1 | TCP acceptor threads (connections are served by the pool above) |
| `JDns.adminBindAddress` | loopback | Admin port listen address (`0.0.0.0` for all interfaces) |
| `JDns.adminSecret` | none | Shared secret for the admin port (challenge-response). Without it only local clients are accepted. `DnsAdminClient` reads the same property |
| `JDns.adminMaxConnections` | 8 | Admin sessions at once |
| `JDns.adminIdleTimeout` | 600000 | Idle admin sessions are closed after this many ms |
| `JDns.useDataBase` | only if `JDns.jdbcURL` is set | Use the database for common domains and dynamic records |
| `JDns.exitOnFatalError` | true (standalone) | Halt the process on a JVM error (see above) |
