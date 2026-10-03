from rich.console import Console


def banner() -> str:
    return """
 █████╗ ██╗   ██╗████████╗ ██████╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗
███████║██║   ██║   ██║   ██║   ██║
██╔══██║██║   ██║   ██║   ██║   ██║
██║  ██║╚██████╔╝   ██║   ╚██████╔╝
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝
        ARGUS v0.3 — recon suite
"""


def show_menu() -> None:
    console = Console()
    console.print("""
1  — Port scan: FULL 65535 + fingerprint
2  — Port scan: TOP-110 + fingerprint
3  — Port scan: ALL ports (быстрый, без фнгерпринта)
4  — Port scan: FULL (aggressive)
5  — Port scan: TOP (aggressive)
─────────────────────────────
6  — DNS recon
7  — WHOIS recon
8  — crt.sh subdomains
10 — Web recon
─────────────────────────────
S  — Subdomain brute-force
T  — Tech fingerprint
H  — Export HTML report
─────────────────────────────
A  — Run ALL recon
Q  — Полный цикл + AI-анализ
0  — Exit
""")
