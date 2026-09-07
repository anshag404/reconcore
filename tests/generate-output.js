/**
 * Generates the parsed JSON output file from mock XML.
 * Usage: node tests/generate-output.js
 */
const fs = require("fs");
const path = require("path");
const { parseNmapXml } = require("../src/services/parser");

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

(async () => {
  const outDir = path.join(__dirname, "output");
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  const result = await parseNmapXml(MOCK_XML);
  const outPath = path.join(outDir, "parsed-scan.json");
  fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
  console.log(`✅  Saved to ${outPath}`);
})();
