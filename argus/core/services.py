"""Справочник сервисов/портов и эвристики пассивного фнгерпринтинга ОС.

Полностью офлайн: никаких внешних API и токенов.
"""
from __future__ import annotations

# порт -> (имя сервиса, категория)
SERVICE_DB: dict[int, tuple[str, str]] = {
    20: ("ftp-data", "file"), 21: ("ftp", "file"), 22: ("ssh", "remote"),
    23: ("telnet", "remote"), 25: ("smtp", "mail"), 43: ("whois", "misc"),
    53: ("dns", "network"), 69: ("tftp", "file"), 79: ("finger", "legacy"),
    80: ("http", "web"), 81: ("http-alt", "web"), 88: ("kerberos", "auth"),
    106: ("pop3pw", "legacy"), 110: ("pop3", "mail"), 111: ("rpcbind", "rpc"),
    113: ("ident", "legacy"), 123: ("ntp", "network"), 135: ("msrpc", "windows"),
    137: ("netbios-ns", "windows"), 138: ("netbios-dgm", "windows"),
    139: ("netbios-ssn", "windows"), 143: ("imap", "mail"), 161: ("snmp", "monitoring"),
    162: ("snmptrap", "monitoring"), 179: ("bgp", "network"), 199: ("smux", "monitoring"),
    389: ("ldap", "auth"), 427: ("svrloc", "network"), 443: ("https", "web"),
    444: ("snmp-add", "monitoring"), 445: ("microsoft-ds", "windows"),
    465: ("smtps", "mail"), 512: ("exec", "legacy"), 513: ("login", "legacy"),
    514: ("syslog", "legacy"), 515: ("printer", "print"), 520: ("route", "network"),
    523: ("ibm-db2", "db"), 548: ("afp", "file"), 554: ("rtsp", "media"),
    587: ("submission", "mail"), 616: ("sco-devmgr", "legacy"), 631: ("ipp", "print"),
    664: ("openvpn-tcp", "vpn"), 666: ("doom", "misc"), 700: ("epp", "misc"),
    800: ("mdbs_daemon", "db"), 801: ("device", "misc"), 873: ("rsync", "file"),
    880: ("cdp-sock", "legacy"), 902: ("vmware-auth", "virtualization"),
    903: ("ssl-vnc", "virtualization"), 981: ("ssl-remote", "web"),
    988: ("cybercash", "legacy"), 990: ("ftps", "file"), 992: ("telnets", "legacy"),
    993: ("imaps", "mail"), 995: ("pop3s", "mail"), 999: ("iss-realseye", "legacy"),
    1000: ("cadlock", "legacy"), 1001: ("tslock", "legacy"), 1025: ("LSM / blackduck", "misc"),
    1080: ("socks", "proxy"), 1093: ("proofd", "misc"), 1158: ("cisco-sccp", "voip"),
    1433: ("mssql", "db"), 1521: ("oracle-tns", "db"), 1720: ("h323q931", "voip"),
    1723: ("pptp", "vpn"), 1755: ("wms", "media"), 1761: ("cert", "legacy"),
    1863: ("msnm", "im"), 2000: ("cisco-sccp-alt", "voip"), 2049: ("nfs", "file"),
    2121: ("ccproxy-ftp", "proxy"), 2301: ("compaqdiag", "hardware"),
    2383: ("lms", "monitoring"), 2394: ("mgmt-ssl", "hardware"), 2399: ("emcs-xstp-cs", "backup"),
    24554: ("quickbcp", "db"), 25000: ("sip", "voip"), 27017: ("mongodb", "db"),
    27018: ("mongodb-con", "db"), 27019: ("cropicaport", "db"),
    28000: ("http-mgmt", "web"), 2811: ("magpi-cbs", "legacy"),
    3000: ("gbhtp / pbr", "dev"), 3128: ("squid-http", "proxy"), 3268: ("globalcatLDAP", "auth"),
    3269: ("globalcatLDAPssl", "auth"), 3299: ("ipsec-msft", "vpn"),
    3306: ("mysql", "db"), 3333: ("dec-notes", "legacy"), 3372: ("tipc", "db"),
    3389: ("ms-wbt-server (RDP)", "remote"), 3476: ("nppmp", "hardware"),
    3493: ("nut", "hardware"), 3517: ("802-11-tls", "auth"), 3689: ("ddns-auth", "network"),
    3690: ("svn", "vcs"), 4000: ("terabase", "db"), 4045: ("locksmith", "legacy"),
    4125: ("rsvp-envelope", "network"), 4126: ("ddm-radgl", "legacy"),
    4444: ("metasploit-default", "security"), 4446: ("nbserver", "backup"),
    4449: ("jetdirect", "print"), 4550: ("gds-adwiw", "legacy"),
    4662: ("edonkey", "p2p"), 4848: ("modbus", "scada"), 4899: ("aptx", "remote"),
    4998: ("ica", "remote"), 5000: ("upnp / commplex-main", "network"),
    5001: ("commplex-link", "network"), 5003: ("filemaker", "db"),
    5004: ("rtp", "media"), 5009: ("airport-admin", "hardware"),
    5050: ("mmcc", "voip"), 5051: ("sdp", "voip"), 5060: ("sip", "voip"),
    5061: ("sips", "voip"), 5190: ("aol", "im"), 5214: ("hpvt", "hardware"),
    5221: ("3com-amp3", "legacy"), 5222: ("xmpp-client", "im"), 5225: ("xmpp", "im"),
    5226: ("xmpp", "im"), 5269: ("xmpp-server", "im"), 5280: ("xmpp", "im"),
    5298: ("presence", "im"), 5353: ("zeroconf/mDNS", "network"),
    5357: ("wsd", "windows"), 5405: ("pcduo-old", "backup"), 5432: ("postgresql", "db"),
    5443: ("wpss", "web"), 5480: ("vclient", "db"), 5550: ("sdologin", "backup"),
    5555: ("freeciv", "game"), 5560: ("xdb", "backup"), 5631: ("esmagent", "monitoring"),
    5633: ("bmongodb", "db"), 5666: ("nrpe", "monitoring"), 5800: ("vnc-http", "remote"),
    5801: ("vnc-http-1", "remote"), 5802: ("vnc-http-2", "remote"),
    5900: ("vnc", "remote"), 5901: ("vnc-1", "remote"), 5902: ("vnc-2", "remote"),
    5903: ("vnc-3", "remote"), 5910: ("cm", "remote"), 5911: ("identity-shift", "remote"),
    5925: ("whatsmyport", "debug"), 5959: ("cwin", "remote"), 5960: ("http-indirect", "remote"),
    5961: ("heartbeat", "remote"), 5962: ("indy", "remote"), 5963: ("identify-supply", "remote"),
    6000: ("x11", "remote"), 6001: ("x11-1", "remote"), 6007: ("ncr-tdi", "backup"),
    6101: ("backup-express", "backup"), 6156: ("policy-server", "network"),
    6346: ("gnutella-svc", "p2p"), 6666: ("irc", "im"), 6667: ("irc", "im"),
    6668: ("irc", "im"), 6669: ("irc", "im"), 6689: ("tsa", "legacy"),
    6969: ("acme-clients", "legacy"), 7000: ("candp", "legacy"), 7001: ("afs3-vlserver", "legacy"),
    7002: ("afs3-kaserver", "legacy"), 7010: ("upsd", "hardware"), 7070: ("real-arman", "legacy"),
    7100: ("font-service", "legacy"), 7103: ("BNB", "legacy"), 7200: ("fiddler", "debug"),
    7201: ("dlr", "legacy"), 7435: ("sun-prc", "legacy"), 7443: ("oracle-ftps", "web"),
    7512: ("mrma", "legacy"), 7878: ("cobolint", "legacy"), 7938: ("bddm", "backup"),
    7999: ("cbt", "legacy"), 8000: ("http-alt", "web"), 8001: ("vcom-tunnel", "debug"),
    8002: ("teradataordbms", "db"), 8007: ("ajp12", "web"), 8008: ("http-alt", "web"),
    8009: ("ajp13", "web"), 8010: ("xmpp2", "im"), 8011: ("raycatcher", "debug"),
    8021: ("intu-ec-svcdisc", "monitoring"), 8022: ("envelope-lwp", "mail"),
    8031: ("vras-cli", "db"), 8042: ("fs", "legacy"), 8043: ("rtdb", "legacy"),
    8044: ("80s-app", "legacy"), 8045: ("omnipatient", "medical"), 8046: ("omnidbSession", "medical"),
    8047: ("omnidbSession-2", "medical"), 8048: ("omnidbSession-3", "medical"),
    8049: ("listen", "legacy"), 8060: ("weblogic-cluster", "web"), 8080: ("http-proxy", "web"),
    8081: ("blackice-alerts", "security"), 8082: ("blackice", "security"),
    8083: ("us-srv", "web"), 8084: ("fs-agent", "web"), 8085: ("wins", "windows"),
    8086: ("mtini", "legacy"), 8087: ("LocationServer", "network"), 8088: ("radan-http", "web"),
    8089: ("nvme-disc", "network"), 8090: ("xmltec-xmlmail", "web"), 8093: ("napster", "p2p"),
    8099: ("probe", "debug"), 8100: ("xprint-server", "print"), 8181: ("unknown", "misc"),
    8192: ("mediabot", "p2p"), 8193: ("endropen", "legacy"), 8194: ("bench-police", "legacy"),
    8200: ("trivnet1", "legacy"), 8400: ("gvmd", "web"), 8443: ("https-alt", "web"),
    8500: ("fmtp", "legacy"), 8600: ("tgp", "legacy"), 8652: ("status-sc", "legacy"),
    8654: ("pearson-plus", "legacy"), 8701: ("abt", "legacy"), 8873: ("dx-instrument", "legacy"),
    8888: ("sun-answerbook", "web"), 8899: ("jfjs", "legacy"), 9000: ("cs-listener", "web"),
    9001: ("tor-orport", "proxy"), 9002: ("newlixdevwizard", "legacy"),
    9003: ("openpgp-card", "auth"), 9040: ("pds", "legacy"), 9090: ("zeus-admin", "web"),
    9091: ("xmltec-xmlmail", "web"), 9099: ("ldap-admin", "auth"),
    9100: ("jetdirect / printer", "print"), 9101: ("dragonlr", "legacy"),
    9102: ("jetdirect", "print"), 9111: ("DragonLockSmith", "legacy"),
    9200: ("elasticsearch / wap-wml", "db"), 9207: ("mxit", "im"), 9220: ("kuprp", "legacy"),
    9290: ("sonet", "legacy"), 9415: ("ipy", "legacy"), 9418: ("git", "vcs"),
    9485: ("nmoceimgd", "legacy"), 9500: ("ismserver", "legacy"), 9535: ("mango-alert", "legacy"),
    9593: ("cba8", "legacy"), 9594: ("lmr-server", "legacy"), 9595: ("ommapping", "legacy"),
    9876: ("session-001", "legacy"), 9898: ("monkeycom", "legacy"), 9900: ("iua", "voip"),
    9943: ("imaps-nse", "mail"), 9944: ("sharedtree", "legacy"), 9945: ("vsiface", "legacy"),
    9998: ("distinct32", "legacy"), 9999: ("distinct", "legacy"), 10000: ("network-database / snapp", "web"),
    10001: ("scp-config", "hardware"), 10005: ("star6g", "legacy"), 10082: ("amandaidx", "backup"),
    11110: ("sctp-tunneling", "tunnel"), 11111: ("vce", "legacy"), 11371: ("hkps", "auth"),
    12000: ("cassandranode", "db"), 12345: ("italk", "legacy"), 13456: ("sudlong", "legacy"),
    14238: ("grblld", "legacy"), 15999: ("vtp", "legacy"), 20000: ("dnp3 / userlock", "scada"),
    21571: ("learnerfree", "legacy"), 22939: ("anticimex", "legacy"), 23322: ("snif-gse", "legacy"),
    23502: ("date-as-mail", "legacy"), 24444: ("zk-shell-internal", "dev"),
    26470: ("watchdog", "monitoring"), 27782: ("trust-tunnel", "tunnel"),
    31337: ("elite", "legacy"), 32768: ("filenet-rpc", "rpc"), 32769: ("filenet-tms", "rpc"),
    33333: ("procluster", "legacy"), 34444: ("parsec-armageddon", "game"),
    34573: ("zabbix-trapper", "monitoring"), 35500: ("ttptech", "legacy"),
    38292: ("polaris", "legacy"), 40000: ("queen / systemmate", "legacy"),
    40911: ("dvc", "legacy"), 41511: ("unicell", "legacy"), 44334: ("cloudhelp", "web"),
    44444: ("tinytfake", "legacy"), 47001: ("firewall", "security"),
    50002: ("digital-vodka", "legacy"), 50003: ("cmf", "legacy"), 54328: ("storevault", "backup"),
    55055: ("xue-trader", "legacy"), 55555: ("fiveoutlook", "legacy"),
    56798: ("dual-quark", "legacy"), 57301: ("dec-byte", "legacy"), 57797: ("ptr", "legacy"),
    60020: ("backdoor-known", "security"), 60443: ("webmonitor", "monitoring"),
    61532: ("metasploit", "security"), 62821: ("labsoft-pvl", "legacy"),
    63463: ("samba-glacier", "legacy"), 64623: ("eshare", "legacy"), 64680: ("mosaix", "legacy"),
    65000: ("mac-shield-vnc", "remote"), 65129: ("codespan-provision", "legacy"),
    65432: ("loglaport", "legacy"),
    # дополнительные известные
    33060: ("mysqlx", "db"), 6379: ("redis", "db"), 5984: ("couchdb", "db"),
    9200: ("elasticsearch", "db"), 5601: ("kibana", "monitoring"), 5985: ("winrm", "windows"),
    5986: ("winrm-ssl", "windows"), 2379: ("etcd", "dev"), 2380: ("etcd-server", "dev"),
    6443: ("kube-apiserver", "dev"), 10250: ("kubelet", "dev"), 9093: ("alertmanager", "monitoring"),
    9094: ("thrift", "dev"), 15672: ("rabbitmq-mgmt", "dev"), 5672: ("amqp", "dev"),
    11211: ("memcached", "db"), 27015: ("mongodb", "db"), 9300: ("mongodb-svc", "db"),
    3240: ("pulseaudio", "media"), 8765: ("thinkd", "dev"), 50000: ("intuit-epm", "legacy"),
    49152: ("dynamic", "misc"), 8088: ("hadoop", "db"), 16000: ("fpm-exporter", "dev"),
    9103: ("liteypop", "legacy"), 6123: ("partitionmagik", "legacy"),
}


def service_name(port: int) -> str:
    name, _ = SERVICE_DB.get(port, ("unknown", "misc"))
    return name


def service_category(port: int) -> str:
    _, cat = SERVICE_DB.get(port, ("unknown", "misc"))
    return cat


# ---------------------------------------------------------------------------
# Пассивная OS-разведка по открытым портам и баннерам (без активных зондов).
# ---------------------------------------------------------------------------

_WINDOWS_ONLY_PORTS = {135, 139, 445, 1433, 5985, 5986, 3389}
_LINUX_HINTS = {"ssh", "apache", "nginx", "ubuntu", "debian", "linux", "glibc"}
_WINDOWS_HINTS = {"microsoft", "ms-wbt", "iis", "windows", "smb", "netbios", "exchange"}
_APPLIANCE_HINTS = {
    "synology": "NAS Synology DSM",
    "qnap": "NAS QNAP QTS",
    "ubiquiti": "Ubiquiti UniFi (Linux-based)",
    "mikrotik": "MikroTik RouterOS",
    "cisco": "Cisco IOS/NX-OS",
    "juniper": "Juniper Junos",
    "fortinet": "Fortinet FortiOS",
    "pfsense": "pfSense (FreeBSD-based)",
    "fritzbox": "AVM FRITZ!Box (Linux-based)",
    "huawei": "Huawei VRP",
    "aruba": "ArubaOS",
    "zoneminder": "ZoneMinder appliance",
    "docker": "Docker host (Linux)",
    "kubernetes": "Kubernetes node",
    "proxmox": "Proxmox VE (Debian-based)",
    "esxi": "VMware ESXi hypervisor",
    "veeam": "Veeam Backup (Windows)",
    "printer": "Принтер/МФУ (встроенная ОС)",
    "honeywell": "Honeywell контроллер",
    "siemens": "Siemens SCADA/PLC",
}


def guess_os(findings: list[dict]) -> dict:
    """Эвристика: предположить ОС/аппаратную платформу по набору находок portscan."""
    ports = sorted({f["data"]["port"] for f in findings if f.get("category") == "port"})
    banners = " \n ".join(
        (f["data"].get("banner") or "") + " " + str(f["data"].get("service", ""))
        for f in findings if f.get("category") == "port"
    ).lower()

    signals: list[str] = []
    scores = {"Windows": 0, "Linux/Unix": 0, "Network/Appliance": 0}

    win_ports = [p for p in ports if p in _WINDOWS_ONLY_PORTS]
    if win_ports:
        scores["Windows"] += len(win_ports) * 2
        signals.append(f"Windows-специфичные порты: {', '.join(map(str, win_ports))}")
    if any(h in banners for h in _WINDOWS_HINTS):
        scores["Windows"] += 3
        signals.append("Баннеры содержат Windows/Microsoft/SMB/IIS сигнатуры")
    if any(h in banners for h in _LINUX_HINTS):
        scores["Linux/Unix"] += 3
        signals.append("Баннеры содержат Linux/OpenSSH/nginx/apache сигнатуры")
    if 22 in ports and "openssh" in banners:
        m = None
        import re
        m = re.search(r"openssh_([\w.~+-]+)", banners)
        if m:
            ver = m.group(1)
            signals.append(f"OpenSSH {ver} — версия собрана для конкретной ОС-платформы")
            scores["Linux/Unix"] += 1
    for key, label in _APPLIANCE_HINTS.items():
        if key in banners:
            scores["Network/Appliance"] += 4
            signals.append(f"Сигнатура устройства/платформы: {label}")

    best = max(scores, key=scores.get) if ports else None
    if not ports:
        return {"os_guess": None, "confidence": "нет данных", "signals": ["Открытые портов не найдено"], "ports": ports}

    total = sum(scores.values())
    confidence = "низкая"
    if total:
        ratio = scores[best] / total
        confidence = "высокая" if ratio >= 0.7 and scores[best] >= 4 else "средняя" if ratio >= 0.5 else "низкая"

    return {
        "os_guess": best if scores[best] > 0 else "Не определена",
        "confidence": confidence,
        "scores": scores,
        "signals": signals or ["Недостаточно сигнатур для определения"],
        "method": "пассивный анализ (порты + баннеры), без активных зондов",
        "ports": ports,
    }
