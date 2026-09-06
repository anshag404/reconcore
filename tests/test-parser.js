/**
 * Test for the Nmap XML parser.
 *
 * Usage:  node tests/test-parser.js
 *
 * Uses a mock XML string that mirrors real nmap -sV -O output,
 * including service detection and OS fingerprinting.
 */
const { parseNmapXml } = require("../src/services/parser");

// ── Mock XML ─────────────────────────────────────────────────────────
// Realistic snippet matching nmap -sV -O -oX - output
const MOCK_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O -oX - scanme.nmap.org"
         start="1788640431" startstr="Sun Sep  6 02:03:51 2026"
         version="7.991" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
<verbose level="0"/>
<debugging level="0"/>

<host starttime="1788640435" endtime="1788640455">
  <status state="up" reason="reset" reason_ttl="250"/>
  <address addr="45.33.32.156" addrtype="ipv4"/>
  <address addr="00:1A:2B:3C:4D:5E" addrtype="mac" vendor="Cisco Systems"/>
  <hostnames>
    <hostname name="scanme.nmap.org" type="user"/>
    <hostname name="scanme.nmap.org" type="PTR"/>
  </hostnames>

  <ports>
    <extraports state="closed" count="992">
      <extrareasons reason="reset" count="992" proto="tcp"/>
    </extraports>

    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack" reason_ttl="44"/>
      <service name="ssh" product="OpenSSH" version="6.6.1p1"
               extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux"
               method="probed" conf="10">
        <cpe>cpe:/a:openbsd:openssh:6.6.1p1</cpe>
        <cpe>cpe:/o:linux:linux_kernel</cpe>
      </service>
    </port>

    <port protocol="tcp" portid="80">
      <state state="open" reason="syn-ack" reason_ttl="44"/>
      <service name="http" product="Apache httpd" version="2.4.7"
               extrainfo="(Ubuntu)" method="probed" conf="10">
        <cpe>cpe:/a:apache:http_server:2.4.7</cpe>
      </service>
    </port>

    <port protocol="tcp" portid="25">
      <state state="filtered" reason="no-response" reason_ttl="0"/>
      <service name="smtp" method="table" conf="3"/>
    </port>

    <port protocol="tcp" portid="9929">
      <state state="open" reason="syn-ack" reason_ttl="44"/>
      <service name="nping-echo" product="Nping echo"
               method="probed" conf="10"/>
    </port>
  </ports>

  <os>
    <osmatch name="Linux 3.2 - 4.9" accuracy="95">
      <osclass type="general purpose" vendor="Linux" osfamily="Linux"
               osgen="3.X" accuracy="95">
        <cpe>cpe:/o:linux:linux_kernel:3</cpe>
      </osclass>
      <osclass type="general purpose" vendor="Linux" osfamily="Linux"
               osgen="4.X" accuracy="95">
        <cpe>cpe:/o:linux:linux_kernel:4</cpe>
      </osclass>
    </osmatch>
    <osmatch name="Linux 3.10" accuracy="90">
      <osclass type="general purpose" vendor="Linux" osfamily="Linux"
               osgen="3.X" accuracy="90">
        <cpe>cpe:/o:linux:linux_kernel:3.10</cpe>
      </osclass>
    </osmatch>
  </os>

</host>

<runstats>
  <finished time="1788640455" timestr="Sun Sep  6 02:04:15 2026"
            summary="Nmap done at Sun Sep  6 02:04:15 2026; 1 IP address (1 host up) scanned in 23.91 seconds"
            elapsed="23.91" exit="success"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>`;

// ── Run test ─────────────────────────────────────────────────────────
(async () => {
  console.log("🔬  Parsing mock Nmap XML...\n");
  console.log("─".repeat(60));

  try {
    const result = await parseNmapXml(MOCK_XML);

    console.log("\n✅  Parsed JSON:\n");
    console.log(JSON.stringify(result, null, 2));

    // ── Quick assertions ─────────────────────────────────────────────
    console.log("\n" + "─".repeat(60));
    console.log("📋  Quick validation:\n");

    const host = result.hosts[0];
    const openPorts = host.ports.filter((p) => p.state.state === "open");

    console.log(`   Hosts found       : ${result.hosts.length}`);
    console.log(`   Host status       : ${host.status.state}`);
    console.log(`   Addresses         : ${host.addresses.map((a) => `${a.addr} (${a.type})`).join(", ")}`);
    console.log(`   Open ports        : ${openPorts.map((p) => p.portId).join(", ")}`);
    console.log(`   OS best guess     : ${host.os?.[0]?.name || "N/A"} (${host.os?.[0]?.accuracy || 0}%)`);
    console.log(`   Scan elapsed      : ${result.runStats.elapsed}s`);
    console.log(`   Services detected : ${openPorts.map((p) => `${p.portId}/${p.service.name}`).join(", ")}`);

    // Assert counts
    const errors = [];
    if (result.hosts.length !== 1) errors.push("Expected 1 host");
    if (openPorts.length !== 3) errors.push(`Expected 3 open ports, got ${openPorts.length}`);
    if (!host.os || host.os.length !== 2) errors.push("Expected 2 OS matches");
    if (host.addresses.length !== 2) errors.push("Expected 2 addresses (IPv4 + MAC)");

    if (errors.length > 0) {
      console.log(`\n❌  Failures: ${errors.join("; ")}`);
      process.exit(1);
    }

    console.log("\n✅  All assertions passed.\n");
  } catch (err) {
    console.error(`\n❌  Parse failed: ${err.message}`);
    process.exit(1);
  }
})();
