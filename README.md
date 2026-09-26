# BjlDns
 The DNS project provides everything you need to run a DNS server and  a DNS client
 and a NsLookup tool.

The intent of this DNS code is to support a large number of domains with very little administrative overhead.
 

 
# Major Features:
 +  Supports unique configuration for any domain.
 +  Supports a common configuration that will be used for any domain that does not have a unique configuration.
 +  Domains may be in a database or file system
 +  Support Dynamic DNS (DDNS) with trivial configuration
 +  Zone file record types: SOA, NS, A, AAAA, CNAME, PTR, MX, TXT, SPF, HINFO, SRV, CAA, HTTPS, SVCB (other types are passed through unchanged when resolving)

Not supported: incremental zone transfer (IXFR is answered with the whole zone), acting as a secondary (incoming NOTIFY gets NOTIMP), RFC 2136 UPDATE (NOTIMP; dynamic records are managed through the admin port), DNSSEC, and the `$GENERATE` zone file directive.

# Zone files

Each `<zone>.txt` file in `JDns.zone.dir` is one zone, in the RFC 1035 master file format:

 +  `$ORIGIN name` sets the origin for relative names and `@` (a relative `$ORIGIN` is relative to the current one). Before the SOA it also names the zone; otherwise the zone is named after the file.
 +  `$TTL ttl` (RFC 2308) is the TTL for the records after it that don't give one. Without `$TTL`, such records get the SOA's TTL, and an SOA without a TTL gets its MINIMUM. A TTL written on a record is used as is.
 +  `$INCLUDE file [origin]` reads another file at that point; a relative path is relative to the including file, and the origin is restored afterwards. Includes can be nested (up to 10 levels; loops are rejected). Name included files something other than `*.txt` (e.g. `hosts.inc`), or they will be loaded as zones of their own. Editing an included file reloads the zone.
 +  HTTPS and SVCB (RFC 9460): `@ IN HTTPS 1 . alpn=h2,h3 port=8443 ipv4hint=192.0.2.1` (ServiceMode; `.` means the owner name) or `www IN HTTPS 0 cdn.example.net.` (AliasMode, no parameters). Keys: `mandatory`, `alpn`, `no-default-alpn`, `port`, `ipv4hint`, `ech` (base64), `ipv6hint` and `keyNNNNN="value"`. Invalid combinations (parameters in AliasMode, a `mandatory` key that is missing, `no-default-alpn` without `alpn`, a key given twice) stop the zone from loading. In answers, the server adds the addresses (A/AAAA) of the target to the additional section when the target is in one of its zones, and for AliasMode also the target's own HTTPS/SVCB records (RFC 9460 4.2).
 +  TTLs can use units: `300`, `30m`, `1h30m`, `2d`, `1w`.
 +  Parentheses can span lines anywhere in a record, and `;` starts a comment except inside quotes.
 +  A zone file that fails to load is reported with the file name and line number (and the previous version keeps being served).
   
 
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

If the server can't start (bad configuration, missing zone directory, a port in use), `DnsServer.main` logs why and exits with -1 (configuration, zones, UDP/TCP sockets) or -2 (admin socket). Applications that embed the server call `start()` and then `awaitStarted(timeoutMs)`, which throws `DnsServer.StartupException` with the cause and stops anything that had started; the server itself never calls `System.exit`.

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
| `JDns.zoneCutReferrals` | true | Names at or below NS records below a zone's apex (a delegation) get a referral (NS + glue, not authoritative) instead of NXDOMAIN / an authoritative answer. Set false if your zones put NS records on ordinary hosts |
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
| `JDns.adminTls` | false | TLS on the admin port, using the standard `javax.net.ssl.keyStore` / `keyStorePassword` properties (client: `javax.net.ssl.trustStore`). `DnsAdminClient` reads the same property. Recommended when `JDns.adminBindAddress` is not loopback: the challenge-response protects the secret, not the session |
| `JDns.adminMaxConnections` | 8 | Admin sessions at once |
| `JDns.adminIdleTimeout` | 600000 | Idle admin sessions are closed after this many ms |
| `JDns.axfrAllow` | none | Addresses / networks allowed to transfer zones over TCP (AXFR, RFC 5936), e.g. `192.0.2.2, 10.0.0.0/8, 2001:db8::/32`. Everyone else gets REFUSED, unless the request is signed with a key in `JDns.axfrKeys` |
| `JDns.notify` | none | Secondaries to send NOTIFY (RFC 1996) to when a zone is loaded or its SOA serial changes, e.g. `192.0.2.2, [2001:db8::2]:53`. Bump the serial when you edit a zone. Dynamic entries don't change the serial, so secondaries only see them at their next transfer |
| `JDns.tsigKeys` | none | TSIG keys (RFC 8945) as `name:algorithm:base64secret`, e.g. `xfr.example:hmac-sha256:...`. Algorithms: hmac-sha256 (recommended), hmac-sha512, hmac-sha384, hmac-sha224, hmac-sha1, hmac-md5. Generate a secret with `openssl rand -base64 32`. A request signed with a known key gets a signed response; a bad signature, an unknown key or a clock too far off (see `JDns.tsigFudge`) gets NOTAUTH and is not answered |
| `JDns.tsigKeyFile` | none | A file of TSIG keys, one `name algorithm secret` per line (`#` comments); relative to `JDns.dnsDir`. Keeps the secrets out of the properties file |
| `JDns.tsigFudge` | 300 | Largest clock difference (seconds, 1-65535) accepted in a signed request; also the fudge used when signing NOTIFY. The window is the smaller of this and the fudge in the request, so a client can't widen it |
| `JDns.axfrKeys` | none | TSIG key names whose signed requests may transfer zones, from any address |
| `JDns.notifyKey` | none | TSIG key to sign NOTIFY messages with; the secondary's answer must then be signed too |
| `JDns.notifyRetries` | 5 | Attempts per NOTIFY |
| `JDns.notifyTimeout` | 2000 | First wait (ms) for a NOTIFY answer, doubled after each attempt |
| `JDns.adminMaxLine` | 8192 | Longest admin command line in bytes; a longer line ends the session |
| `JDns.adminAuthTimeout` | 30000 | With `JDns.adminSecret` set, a session that hasn't authenticated after this many ms is closed |
| `JDns.useDataBase` | only if `JDns.jdbcURL` is set | Use the database for common domains and dynamic records |
| `JDns.exitOnFatalError` | true (standalone) | Halt the process on a JVM error (see above) |
