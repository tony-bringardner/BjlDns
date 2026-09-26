# BjlDns
 The DNS project provides everything you need to run a DNS server and  a DNS client
 and a NsLookup tool.

The intent of this DNS code is to support a large number of domains with very little administrative overhead.
 

 
# Major Features:
 +  Supports unique configuration for any domain.
 +  Supports a common configuration that will be used for any domain that does not have a unique configuration.
 +  Domains may be in a database or file system
 +  Support Dynamic DNS (DDNS) with trivial configuration
 +  Zone file record types: SOA, NS, A, AAAA, CNAME, PTR, MX, TXT, SPF, HINFO, SRV, CAA, HTTPS, SVCB, DS (other types are passed through unchanged when resolving)
 +  DNSSEC: zones are signed by the server itself when it has keys for them, or served as signed by another tool (see below)

Not supported: incremental zone transfer (IXFR is answered with the whole zone), acting as a secondary (incoming NOTIFY gets NOTIMP), NSEC3 opt-out, validating answers from other servers when resolving, and the `$GENERATE` zone file directive.

# Zone files

Each `<zone>.txt` file in `JDns.zone.dir` is one zone, in the RFC 1035 master file format:

 +  `$ORIGIN name` sets the origin for relative names and `@` (a relative `$ORIGIN` is relative to the current one). Before the SOA it also names the zone; otherwise the zone is named after the file.
 +  `$TTL ttl` (RFC 2308) is the TTL for the records after it that don't give one. Without `$TTL`, such records get the SOA's TTL, and an SOA without a TTL gets its MINIMUM. A TTL written on a record is used as is.
 +  `$INCLUDE file [origin]` reads another file at that point; a relative path is relative to the including file, and the origin is restored afterwards. Includes can be nested (up to 10 levels; loops are rejected). Name included files something other than `*.txt` (e.g. `hosts.inc`), or they will be loaded as zones of their own. Editing an included file reloads the zone.
 +  HTTPS and SVCB (RFC 9460): `@ IN HTTPS 1 . alpn=h2,h3 port=8443 ipv4hint=192.0.2.1` (ServiceMode; `.` means the owner name) or `www IN HTTPS 0 cdn.example.net.` (AliasMode, no parameters). Keys: `mandatory`, `alpn`, `no-default-alpn`, `port`, `ipv4hint`, `ech` (base64), `ipv6hint` and `keyNNNNN="value"`. Invalid combinations (parameters in AliasMode, a `mandatory` key that is missing, `no-default-alpn` without `alpn`, a key given twice) stop the zone from loading. In answers, the server adds the addresses (A/AAAA) of the target to the additional section when the target is in one of its zones, and for AliasMode also the target's own HTTPS/SVCB records (RFC 9460 4.2).
 +  TTLs can use units: `300`, `30m`, `1h30m`, `2d`, `1w`.
 +  Parentheses can span lines anywhere in a record, and `;` starts a comment except inside quotes.
 +  A zone file that fails to load is reported with the file name and line number (and the previous version keeps being served).

# Dynamic update (RFC 2136)

Allowed for requests signed with a key in `JDns.updateKeys` (or from `JDns.updateAllow`); everyone else gets REFUSED. Prerequisites, adds and all three kinds of delete are supported, with the RFC's rules (the apex SOA and NS RRset can't be deleted, never the last NS, no other data next to a CNAME). An update is all or nothing.

The zone file is never rewritten. Changes are appended to a journal next to it, `<zone file>.jnl`, before they are served, and replayed on top of the zone file when it is loaded. Each change raises the SOA serial by one and sends NOTIFY to the secondaries. To edit a zone by hand after updates, edit the zone file (it keeps the updates as long as the serial stays the same) or raise its serial to start over: the journal is then renamed `.jnl.old` and not used. Updates can add A, AAAA, NS, CNAME, PTR, MX, TXT, SPF, HINFO, SRV, CAA, HTTPS, SVCB and DS records; other types are REFUSED. A signed zone is signed again after each update. A TXT record keeps one string (several strings are joined).

# DNSSEC

A zone is signed when the key directory (`JDns.dnssecKeyDir`, by default the zone directory) has keys for it. The server signs it when it loads it, after every dynamic update or dynamic entry change, and again before the signatures expire; nothing needs to be run by hand after the keys exist.

1. Make a key: `java -cp bjl_dns.jar:bjl_core.jar:bjl_io.jar us.bringardner.net.dns.dnssec.DnssecKeyTool keygen -d zones example.com`. This writes `Kexample.com.+013+<tag>.key` and `.private` (keep that one secret) and prints the DS record. One key (ECDSA P-256, a combined signing key) is all a zone needs; `-ksk` / `-zsk` make separate key and zone signing keys, `-a` picks the algorithm: ECDSAP256SHA256 (default), ECDSAP384SHA384, ED25519 (Java 15 or later), RSASHA256, RSASHA512. Keys made with BIND's `dnssec-keygen` work too.
2. Start (or wait for the next reload): the zone is served signed.
3. Give the DS record to the parent zone (your registrar). `DnssecKeyTool ds -d zones example.com` prints it again. Until the parent has it, validators treat the zone as unsigned; once it does, they reject answers that don't verify.

What the server does:
 +  Adds the DNSKEY set and an NSEC chain, and signs every RRset: the DNSKEY set with the key signing keys (flags 257), the rest with the zone signing keys (256), or everything with one key if there is only one kind. At a delegation only the DS set and the NSEC are signed; glue is not.
 +  Answers queries with the DO bit with the RRSIGs, and proves what doesn't exist with NSEC records (NXDOMAIN, NODATA, wildcards, delegations without a DS). Queries without the DO bit get the same answers as before.
 +  NSEC3 (RFC 5155) instead of NSEC for the zones in `JDns.dnssecNsec3` (`*` for all): the chain holds hashes of the names, so it can't be walked to list the zone. The defaults follow RFC 9276 (0 extra iterations, no salt, no opt-out); `JDns.dnssecNsec3Iterations` (at most 100) and `JDns.dnssecNsec3Salt` change them. Switching a zone between NSEC and NSEC3 re-signs it.
 +  DS records go in the parent zone file at the delegation, e.g. `child IN DS 12345 13 2 <digest>`. A DS query is answered from the parent, even when the server serves the child too.
 +  Signatures are valid for `JDns.dnssecValidity` (14 days) from an hour ago. When a quarter is left the zone is signed again with the next serial (written to the journal, so it survives a restart) and the secondaries get a NOTIFY. Zone transfers include the signatures.
 +  Key rollover: every key file of a zone is used. A `.key` file without its `.private` file is published in the DNSKEY set but doesn't sign. BIND's timing fields in the `.private` file (`Publish`, `Activate`, `Inactive`, `Delete`, set with `dnssec-settime`) are followed. Adding, removing or changing a key file re-signs the zone.
 +  If a zone can't be signed (e.g. no key has its private file), the error is logged and the previous signatures are served while they are valid, otherwise the zone is served unsigned.

Zones signed elsewhere (for example with BIND's `dnssec-signzone`, NSEC or NSEC3, so the private keys never touch the server): put the signed file in the zone directory as `<zone>.txt`. A zone file with RRSIG records is served with its own DNSKEY, RRSIG, NSEC / NSEC3 and NSEC3PARAM records, with the same answers and proofs as a zone signed here.
 +  Every signature is checked when the zone loads; ones that don't verify or have expired are logged (the zone is still served as the signer made it). Keys in the key directory are not used for it.
 +  The server can't sign changes: dynamic UPDATE is REFUSED, and admin-port dynamic entries in such a zone are served without signatures (logged).
 +  Nothing re-signs it here: a warning is logged every 6 hours from 3 days before the first signature expires. Sign it again and replace the file (a changed file is reloaded).
 +  A zone file with DNSKEY, NSEC or NSEC3 records but no RRSIG is refused.

In a signed zone:
 +  Wildcards follow RFC 4592, as validators expect: `*.example.com` also matches `a.b.example.com`, but never a name that exists or has names below it.
 +  An SOA query for a name other than the apex gets NODATA (the made-up SOA the default zone gives other names can't be signed).
 +  DNSKEY, RRSIG, NSEC, NSEC3 and NSEC3PARAM records can't be added with UPDATE (DS can); in a zone file they make it a zone signed elsewhere.
 +  Names outside the zone itself (the `*.*.` patterns a default zone uses for other domains) are served unsigned.
   
 
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

Set them in the properties file (`JDns.properties`, see below) or with `-D` on the command line; `-D` wins. Every BjlDns property starts with `JDns.`.

A bind address of `localhost` means this host's own name (its network address), not the loopback interface, so the server is reachable from the network; a warning is logged. Use `127.0.0.1` to listen on loopback only.

### Files and zones

| Property | Default | Meaning |
|---|---|---|
| `JDns.properties` | `JDns.properties` (current directory) | The properties file to load at startup |
| `JDns.dnsDir` | `/data/services/dns/config` | Directory for the dynamic entries file, the TSIG key file and the root hints (`sbelt.prop`) |
| `JDns.zone.dir` | `zones` | Directory of the zone files (`<zone>.txt`); a changed file is reloaded |
| `JDns.master.zone` | required | The default zone: answers for the common domains (see Major Features) come from it |
| `JDns.dynamicFileName` | `dynamic.txt` | Dynamic entries file, relative to `JDns.dnsDir` (used without a database) |
| `JDns.debug` | true | Debug logging checks; false skips the work of building debug messages |
| `JDns.ra` | true | Recursion available: resolve names that are not in our zones for clients that ask for it |
| `JDns.exitOnFatalError` | true (standalone) | Halt the process on a JVM error (see above) |

### Network

| Property | Default | Meaning |
|---|---|---|
| `JDns.dnsPort` | 53 | DNS port (UDP and TCP) |
| `JDns.bindAddress` | loopback | Listen address |
| `JDns.udpPort` / `JDns.tcpPort` | `JDns.dnsPort` | Per-protocol port |
| `JDns.udp.bindAddress` / `JDns.tcpBindAddress` | `JDns.bindAddress` | Per-protocol listen address |
| `JDns.timeout` | 5000 | Socket timeout (ms) for both protocols |
| `JDns.udpTimeout` / `JDns.tcpTimeout` | `JDns.timeout` | Per-protocol socket timeouts (ms); how often listeners check for shutdown |
| `JDns.udpProcCount` | 10 | UDP listener threads |
| `JDns.tcpProcCount` | 1 | TCP acceptor threads (connections are served by the pool below) |
| `JDns.tcpBacklog` | 10 | TCP listen backlog |
| `JDns.tcpMaxConnections` | 64 | TCP connections served at once; more are closed immediately |
| `JDns.tcpIdleTimeout` | 10000 | An idle TCP connection is closed after this many ms |
| `JDns.udpMaxResponse` | 512 | Largest UDP response (bytes) to clients without EDNS; bigger answers are truncated (TC) and clients retry over TCP |
| `JDns.ednsUdpSize` | 1232 | Largest UDP response to EDNS clients (512–4096; the client's own size is used if smaller). Responses echo an OPT record; EDNS versions other than 0 get BADVERS |
| `JDns.zoneCutReferrals` | true | Names at or below NS records below a zone's apex (a delegation) get a referral (NS + glue, not authoritative) instead of NXDOMAIN / an authoritative answer. Set false if your zones put NS records on ordinary hosts |
| `JDns.dump.file` | none | Write every UDP request and answer to this file (debugging) |

### Resolver (recursion)

| Property | Default | Meaning |
|---|---|---|
| `JDns.resolvers` | 10 | Resolver threads |
| `JDns.resolverMaxBacklog` | 200 | Queued recursive queries; when full, clients get SERVFAIL (a CNAME answer is sent without the target's records). Logged at most every 10 s |
| `JDns.resolveTimeout` | 4000 | Total time (ms) for one resolution, including referrals and CNAME hops |
| `JDns.maxCacheEntries` | 10000 | Resolver cache size (LRU) |
| `JDns.cacheSweepSeconds` | 60 | How often expired cache entries are removed |
| `JDns.maxCacheAge` | 1800000 | Upper bound (ms) on how long anything is cached |
| `JDns.maxNegativeTtl` | 10800 | Upper bound (s) for caching "does not exist" answers |
| `JDns.maxDelegations` | 10000 | Learned delegations kept (LRU) |
| `JDns.delegationMaxAge` | 3600 | Seconds a learned delegation is used before a fresh referral replaces it |

### Admin port

| Property | Default | Meaning |
|---|---|---|
| `JDns.adminPort` | 9999 | Admin port; `DnsAdminClient` connects to it too |
| `JDns.adminHost` | the DNS server NsLookup finds, else localhost | Host `DnsAdminClient` connects to (a command line argument wins) |
| `JDns.adminBindAddress` | loopback | Admin port listen address (`0.0.0.0` for all interfaces) |
| `JDns.adminSecret` | none | Shared secret for the admin port (challenge-response). Without it only local clients are accepted. `DnsAdminClient` reads the same property |
| `JDns.adminTls` | false | TLS on the admin port, using the standard `javax.net.ssl.keyStore` / `keyStorePassword` properties (client: `javax.net.ssl.trustStore`). `DnsAdminClient` reads the same property. Recommended when `JDns.adminBindAddress` is not loopback: the challenge-response protects the secret, not the session |
| `JDns.adminMaxConnections` | 8 | Admin sessions at once |
| `JDns.adminIdleTimeout` | 600000 | Idle admin sessions are closed after this many ms |
| `JDns.adminMaxLine` | 8192 | Longest admin command line in bytes; a longer line ends the session |
| `JDns.adminAuthTimeout` | 30000 | With `JDns.adminSecret` set, a session that hasn't authenticated after this many ms is closed |

### Database

| Property | Default | Meaning |
|---|---|---|
| `JDns.useDataBase` | only if `JDns.jdbcURL` is set | Use the database for common domains and dynamic records |
| `JDns.jdbcURL` | none | JDBC URL of the database |
| `JDns.jdbcClass` | none | JDBC driver class to load (not needed for JDBC 4 drivers on the class path) |
| `JDns.jdbcUser` / `JDns.jdbcPassword` | none | Database login |

The standalone `DynamicDns` class uses the same four `JDns.jdbc*` properties.

### Zone transfer, TSIG, dynamic update

| Property | Default | Meaning |
|---|---|---|
| `JDns.axfrAllow` | none | Addresses / networks allowed to transfer zones over TCP (AXFR, RFC 5936), e.g. `192.0.2.2, 10.0.0.0/8, 2001:db8::/32`. Everyone else gets REFUSED, unless the request is signed with a key in `JDns.axfrKeys` |
| `JDns.axfrKeys` | none | TSIG key names whose signed requests may transfer zones, from any address |
| `JDns.notify` | none | Secondaries to send NOTIFY (RFC 1996) to when a zone is loaded or its SOA serial changes, e.g. `192.0.2.2, [2001:db8::2]:53`. Bump the serial when you edit a zone. Dynamic entries don't change the serial, so secondaries only see them at their next transfer |
| `JDns.notifyKey` | none | TSIG key to sign NOTIFY messages with; the secondary's answer must then be signed too |
| `JDns.notifyRetries` | 5 | Attempts per NOTIFY |
| `JDns.notifyTimeout` | 2000 | First wait (ms) for a NOTIFY answer, doubled after each attempt |
| `JDns.tsigKeys` | none | TSIG keys (RFC 8945) as `name:algorithm:base64secret`, e.g. `xfr.example:hmac-sha256:...`. Algorithms: hmac-sha256 (recommended), hmac-sha512, hmac-sha384, hmac-sha224, hmac-sha1, hmac-md5. Generate a secret with `openssl rand -base64 32`. A request signed with a known key gets a signed response; a bad signature, an unknown key or a clock too far off (see `JDns.tsigFudge`) gets NOTAUTH and is not answered |
| `JDns.tsigKeyFile` | none | A file of TSIG keys, one `name algorithm secret` per line (`#` comments); relative to `JDns.dnsDir`. Keeps the secrets out of the properties file |
| `JDns.tsigFudge` | 300 | Largest clock difference (seconds, 1-65535) accepted in a signed request; also the fudge used when signing NOTIFY. The window is the smaller of this and the fudge in the request, so a client can't widen it |
| `JDns.updateKeys` | none | TSIG key names whose signed dynamic UPDATE requests (RFC 2136, e.g. `nsupdate -k`) may change zones |
| `JDns.updateAllow` | none | Addresses / networks allowed to send unsigned UPDATE requests. Prefer `JDns.updateKeys` |

### DNSSEC

| Property | Default | Meaning |
|---|---|---|
| `JDns.dnssecKeyDir` | `JDns.zone.dir` | Directory of the DNSSEC key files (`K<zone>.+<alg>+<tag>.key` and `.private`). A zone with keys there is signed |
| `JDns.dnssecValidity` | 14d | How long DNSSEC signatures are valid (at least 1h); zones are signed again when a quarter of it is left |
| `JDns.dnssecNsec3` | none | Zones to sign with NSEC3 instead of NSEC, e.g. `example.com, example.org`, or `*` for all |
| `JDns.dnssecNsec3Iterations` | 0 | NSEC3 extra hash iterations (0-100; RFC 9276 recommends 0) |
| `JDns.dnssecNsec3Salt` | - | NSEC3 salt in hex, `-` for none (RFC 9276 recommends none) |

### Logging (BjlCore)

Logging comes from the BjlCore library, whose property names are its own: `LogLevel` (default ERROR; e.g. DEBUG, INFO), `<logger name>.LogLevel` for one logger, `LogFile` (default: standard output) and `ILogger` (the logger class).

### Renamed properties

These were renamed so all names start with `JDns.`. The old names still work but log a warning; the new name wins when both are set.

| Old name | New name |
|---|---|
| `UDPProcCount` | `JDns.udpProcCount` |
| `TCPProcCount` | `JDns.tcpProcCount` |
| `Resolver.maxBacklog` | `JDns.resolverMaxBacklog` |
| `name`, `port` (DnsAdminClient) | `JDns.adminHost`, `JDns.adminPort` |
| `DnsDriver`, `DynUrl`, `DynUser`, `DynPassword` (DynamicDns) | `JDns.jdbcClass`, `JDns.jdbcURL`, `JDns.jdbcUser`, `JDns.jdbcPassword` |
