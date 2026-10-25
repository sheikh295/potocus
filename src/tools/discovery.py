"""Kali tool discovery — index manuals into ChromaDB and ``search_kali_tools``."""

from __future__ import annotations

import logging
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal

from src.memory.vectorstore import WorkspaceVectorStore
from src.utils.config import PROJECT_ROOT

logger = logging.getLogger("potocus.discovery")

TOOL_NAME = "search_kali_tools"

# Project-shipped seed manuals used when a binary is not on PATH (Mac/dev).
# On Kali, live ``--help`` capture replaces these during ``tools index``.
SEED_DIR = PROJECT_ROOT / "data" / "kali_tools"

SourceKind = Literal["live", "seed"]

# High-signal Kali / common offensive tools. Indexer probes PATH for each name.
KALI_TOOL_CATALOG: tuple[str, ...] = (
    # --- Original List (preserved) ---
    "nmap", "masscan", "rustscan", "amass", "subfinder", "httpx", "whatweb",
    "gobuster", "feroxbuster", "ffuf", "dirb", "nikto", "nuclei", "wpscan",
    "sqlmap", "hydra", "medusa", "ncrack", "john", "hashcat", "enum4linux",
    "enum4linux-ng", "smbclient", "smbmap", "rpcclient", "snmpwalk",
    "onesixtyone", "Responder", "responder", "impacket-psexec",
    "impacket-wmiexec", "impacket-smbexec", "evil-winrm", "msfconsole",
    "msfvenom", "searchsploit", "crackmapexec", "netexec",
    "bloodhound-python", "ldapsearch", "dig", "whois", "host",
    "traceroute", "curl", "wget", "nc", "ncat", "tcpdump", "tshark",
    "wireshark", "chisel", "ssh", "proxychains4", "proxychains",
    "iw", "iwconfig", "airmon-ng", "airodump-ng", "aireplay-ng",
    "aircrack-ng", "packetforge-ng", "wifite", "kismet", "reaver",
    "bully", "wash", "pixiewps",

    # --- Reconnaissance & OSINT ---
    "assetfinder", "sublist3r", "theHarvester", "recon-ng", "maltego",
    "dnsrecon", "dnsenum", "fierce", "dnsx", "massdns", "altdns",
    "dnsgen", "dnstwist", "gospider", "hakrawler", "gau", "waybackurls",
    "httprobe", "gowitness", "eyewitness", "aquatone", "wafw00f",
    "whatweb", "cmseek", "photon", "osrframework", "sherlock",
    "instaloader", "linkedin2username", "emailharvester", "h8mail",
    "exiftool", "metagoofil", "google-nexus-tools", "bing-ip2hosts",
    "cloud_enum", "cloudbrute", "certgraph", "tlsx", "naabu",

    # --- Web Application & API Testing ---
    "burpsuite", "zaproxy", "caido", "caido-cli", "arjun", "paramspider",
    "x8", "kiterunner", "kr", "jwt_tool", "jsp-file-browser",
    "gobuster", "dirsearch", "dirb", "dirbuster", "feroxbuster",
    "ffuf", "wfuzz", "dotdotpwn", "commix", "xsstrike", "dalfox",
    "sqlmap", "sqlmate", "bbqsql", "jsql-injection", "wpscan",
    "joomscan", "droopescan", "cmseek", "whatweb", "nikto", "nuclei",
    "nuclei-templates", "wapiti", "skipfish", "vega", "owasp-zap",

    # --- Active Directory & Windows ---
    "bloodhound", "bloodhound-ce-python", "sharphound", "azurehound",
    "certipy", "certipy-ad", "certi", "rubeus", "kerbrute",
    "kerberoast", "asreproast", "ldeep", "adidnsdump", "gpp-decrypt",
    "lapsdumper", "pywerview", "powerview", "ad-ldap-enum",
    "windapsearch", "ldapdomaindump", "ldapsearch", "ldapdomaindump",
    "impacket-ntlmrelayx", "impacket-secretsdump", "impacket-getTGT",
    "impacket-getST", "impacket-GetNPUsers", "impacket-GetUserSPNs",
    "impacket-goldenPac", "impacket-lookupsid", "impacket-rpcdump",
    "impacket-samrdump", "impacket-smbserver", "impacket-ticketer",
    "mitm6", "responder", "ntlmrelayx", "printerbug", "petitpotam",
    "dfscoerce", "coercer", "krbrelayx", "psexec", "wmiexec",
    "smbexec", "atexec", "dcomexec", "evil-winrm", "evil-winrm-py",
    "netexec", "crackmapexec", "smbclient", "smbmap", "rpcclient",
    "enum4linux-ng", "nbtscan", "nbtscan-unixwiz", "regripper",
    "chisel", "ligolo-ng", "ligolo-mp", "proxychains4", "socat",

    # --- Exploitation & C2 ---
    "metasploit-framework", "msfconsole", "msfvenom", "msfpc",
    "searchsploit", "exploitdb", "getsploit", "pompem",
    "havoc", "sliver", "cobalt-strike", "mythic", "empire",
    "poshc2", "koadic", "merlin-server", "merlin-agent",
    "covenant", "shad0w", "hoaxshell", "godoh", "gsocket",
    "pwncat", "pwncat-cs", "routersploit", "beef-xss",
    "armitage", "cobaltstrike", "silenttrinity", "donut",
    "golang-github-binject-go-donut", "shellter", "veil",
    "backdoor-factory", "msf-nasm_shell",

    # --- Password Attacks & Cracking ---
    "hashcat", "john", "johnny", "hydra", "medusa", "ncrack",
    "patator", "crowbar", "brutespray", "changeme", "crack",
    "cewl", "crunch", "cupp", "bopscrk", "princeprocessor",
    "hashid", "name-that-hash", "haiti", "hash-identifier",
    "ophcrack", "rainbowcrack", "rcrack", "samdump2",
    "secretsdump", "pwdump", "fgdump", "mimikatz", "lazagne",
    "LaZagne", "wesng", "windows-exploit-suggester",
    "linux-exploit-suggester", "linux-smart-enumeration",
    "linpeas", "winpeas", "pspy", "unix-privesc-check",
    "bruteforce-luks", "bruteforce-salted-openssl",
    "bruteforce-wallet", "cisco7crack", "dislocker",

    # --- Wireless & RF ---
    "airgeddon", "fluxion", "wifite", "eaphammer", "hostapd-mana",
    "hostapd-wpe", "bettercap", "bettercap-ui", "mdk4", "mdk3",
    "hcxdumptool", "hcxtools", "hcxpcapngtool", "cowpatty",
    "pyrit", "coWPAtty", "fern-wifi-cracker", "kismet", "horst",
    "pixiewps", "reaver", "bully", "wash", "aircrack-ng",
    "airodump-ng", "aireplay-ng", "airmon-ng", "airbase-ng",
    "packetforge-ng", "proxmark3", "rfidiot", "mfoc", "mfcuk",
    "gnuradio", "gqrx", "sdrangel", "inspectrum", "universal-radio-hacker",
    "hackrf", "rtl-sdr", "bladerf", "apple-bleee", "bluetoothctl",
    "bettercap", "wifi-coconut", "hak5-wifi-coconut",

    # --- Forensics & Incident Response ---
    "autopsy", "sleuthkit", "sleuthkit-java", "volatility", "volatility3",
    "binwalk", "foremost", "scalpel", "bulk_extractor", "dcfldd",
    "guymager", "afflib-tools", "libewf-tools", "sleuthkit",
    "magicrescue", "scrounge-ntfs", "testdisk", "photorec",
    "extundelete", "ext4magic", "ntfs-3g", "chntpw",
    "regripper", "pdf-parser", "pdfid", "peepdf", "oledump",
    "oletools", "olevba", "rtfdump", "hachoir", "hashdeep",
    "md5deep", "ssdeep", "xplico", "chaosreader", "tcpflow",
    "networkminer", "capinfos", "tshark", "wireshark",
    "dsniff", "urlsnarf", "msgsnarf", "filesnarf", "mailsnarf",
    "ettercap", "ettercap-graphical", "bettercap", "mitmproxy",

    # --- Reverse Engineering & Binary Analysis ---
    "ghidra", "radare2", "cutter", "rizin", "rizin-cutter",
    "ida-free", "gdb", "gdb-peda", "gef", "pwndbg",
    "x64dbg", "ollydbg", "immunity-debugger", "edb-debugger",
    "ltrace", "strace", "objdump", "readelf", "nm",
    "strings", "file", "ldd", "xxd", "hexdump", "hexwalk",
    "imhex", "angr", "capstone-tool", "keystone-engine",
    "unicorn-engine", "detect-it-easy", "die", "pe-bear",
    "peframe", "pestudio", "cff-explorer", "dnspy", "ilspy",
    "apktool", "dex2jar", "jadx", "jd-gui", "bytecode-viewer",
    "pyinstxtractor", "uncompyle6", "decompyle3", "pycdc",
    "ghidra", "binaryninja", "hopper", "retdec", "snowman",

    # --- Mobile Security ---
    "apktool", "dex2jar", "jadx", "jadx-gui", "mobsf",
    "frida", "objection", "drozer", "android-sdk",
    "adb", "fastboot", "aapt", "aapt2", "zipalign", "apksigner",
    "uber-apk-signer", "dexcalibur", "house", "needle",
    "passionfruit", "ios-deploy", "libimobiledevice",
    "ideviceinstaller", "ifuse", "class-dump", "otool",

    # --- Cloud & Container ---
    "pacu", "cloud_enum", "cloudbrute", "azurehound", "roadtools",
    "awscli", "azure-cli", "gcloud", "eksctl", "kubectl",
    "kustomize", "helm", "cilium-cli", "calicoctl", "cri-tools",
    "trivy", "grype", "syft", "cosign", "docker",
    "docker-compose", "podman", "buildah", "skopeo",
    "peirates", "kube-hunter", "kube-bench", "kubescape",

    # --- Tunneling & Pivoting ---
    "chisel", "ligolo-ng", "ligolo-mp", "proxychains4",
    "proxychains", "proxify", "socat", "sshuttle", "dnscat2",
    "iodine", "ptunnel", "gre tunnel", "gost", "gsocket",
    "merlin-server", "merlin-agent", "neo-regeorg", "regeorg",
    "abptts", "earthworm", "ew", "venom", "goproxy",
    "frp", "ngrok", "cloudflared", "tun2socks", "redsocks",

    # --- Social Engineering & Phishing ---
    "setoolkit", "gophish", "evilginx2", "modlishka", "phishery",
    "king-phisher", "hiddeneye", "socialfish", "blackeye",
    "shellphish", "zphisher", "nexphisher", "advphishing",
    "pyphisher", "credential-phisher", "site-cloner",
    "maskphish", "storm-breaker", "evil-ssdp", "responder",

    # --- Reporting & Collaboration ---
    "faraday", "faraday-cli", "faraday-agent-dispatcher",
    "dradis", "serpico", "pentest-tools", "recon-ng",
    "magictree", "keepnote", "cherrytree", "joplin",
    "obsidian", "maltego", "casefile", "cortana",

    # --- Utility & Miscellaneous ---
    "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet",
    "ssh", "scp", "rsync", "ftp", "sftp", "smbclient",
    "impacket-smbserver", "impacket-ntlmrelayx", "responder",
    "bettercap", "mitmproxy", "mitm6", "arp-scan", "arping",
    "hping3", "fping", "npings", "mtr", "traceroute",
    "dig", "nslookup", "host", "whois", "dnsutils",
    "tcpdump", "tshark", "wireshark", "termshark",
    "gparted", "dd", "dcfldd", "dc3dd", "gddrescue",
    "kali-tweaks", "kali-autopilot", "searchsploit",
    "gitleaks", "gitxray", "trufflehog", "semgrep",
    "bandit", "shellcheck", "clang", "gcc", "g++",
    "python3", "pip", "pipx", "ruby", "gem", "go", "cargo",
    "jq", "yq", "xmllint", "base64", "openssl", "gpg",
    "ssh-keygen", "ssh-agent", "ssh-add", "gpg-agent",

    # --- Wireless (Expanded) ---
    "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
    "airbase-ng", "packetforge-ng", "airdecap-ng", "airdecloak-ng",
    "airolib-ng", "airtun-ng", "ivstools", "kismet", "kismet-capture",
    "horst", "wifite", "wireshark", "tshark", "hcxdumptool",
    "hcxtools", "hcxpcaptool", "hcxpcapngtool", "cowpatty",
    "pyrit", "reaver", "bully", "wash", "pixiewps",
    "mdk4", "mdk3", "eaphammer", "hostapd-mana", "hostapd-wpe",
    "fluxion", "airgeddon", "wifi-pumpkin", "bettercap",
    "fern-wifi-cracker", "wepcrack", "wesside-ng", "easside-ng",
)

@dataclass(frozen=True)
class ToolManual:
    """One tool manual document ready for embedding."""

    name: str
    text: str
    source: SourceKind
    binary_path: str | None = None


@dataclass(frozen=True)
class IndexReport:
    """Summary of a tool-index run."""

    platform: str
    live_count: int
    seed_count: int
    skipped: int
    total_upserted: int
    collection_size: int
    tools: tuple[str, ...]


def seed_dir() -> Path:
    """Return the path to shipped seed manuals."""
    return SEED_DIR


def capture_help(binary: str, *, timeout_seconds: float = 8.0) -> str | None:
    """
    Capture ``--help`` / ``-h`` / ``help`` output for an installed binary.

    Returns None when nothing useful is produced.
    """
    path = shutil.which(binary)
    if not path:
        return None

    candidates: list[list[str]] = [
        [path, "--help"],
        [path, "-h"],
        [path, "help"],
    ]
    for argv in candidates:
        try:
            completed = subprocess.run(  # noqa: S603
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        text = ((completed.stdout or "") + "\n" + (completed.stderr or "")).strip()
        if len(text) >= 40:
            return text[:50_000]
    return None


def load_seed_manual(name: str, directory: Path | None = None) -> str | None:
    """Load a seed manual for ``name`` if present."""
    root = directory or seed_dir()
    path = root / f"{name}.txt"
    if not path.exists():
        # Case-insensitive fallback (e.g. Responder vs responder).
        matches = list(root.glob(f"{name}.txt")) + [
            p for p in root.glob("*.txt") if p.stem.lower() == name.lower()
        ]
        if not matches:
            return None
        path = matches[0]
    text = path.read_text(encoding="utf-8").strip()
    return text if text else None


def collect_manuals(
    *,
    catalog: Iterable[str] = KALI_TOOL_CATALOG,
    prefer_live: bool = True,
    include_seed_fallback: bool = True,
    seed_directory: Path | None = None,
) -> list[ToolManual]:
    """
    Build manuals for catalog tools.

    - **live**: binary on PATH → capture help (preferred on Kali).
    - **seed**: not installed → use shipped ``data/kali_tools/<name>.txt`` (Mac/dev).

    Set ``include_seed_fallback=False`` on Kali if you only want real installs.
    """
    manuals: list[ToolManual] = []
    seen: set[str] = set()
    for name in catalog:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)

        live_text = capture_help(name) if prefer_live else None
        if live_text:
            manuals.append(
                ToolManual(
                    name=name,
                    text=live_text,
                    source="live",
                    binary_path=shutil.which(name),
                )
            )
            continue

        if include_seed_fallback:
            seed_text = load_seed_manual(name, seed_directory)
            if seed_text:
                manuals.append(
                    ToolManual(name=name, text=seed_text, source="seed", binary_path=None)
                )
    return manuals


def index_tools(
    store: WorkspaceVectorStore,
    *,
    manuals: list[ToolManual] | None = None,
    reset: bool = False,
    include_seed_fallback: bool = True,
) -> IndexReport:
    """
    Embed tool manuals into the workspace ``kali_tools`` collection.

    ``reset=True`` drops the collection first (clean reindex on Kali).
    """
    if reset:
        store.delete_collection(WorkspaceVectorStore.TOOLS_COLLECTION)

    docs = manuals if manuals is not None else collect_manuals(
        include_seed_fallback=include_seed_fallback
    )
    ids = [f"tool:{m.name.lower()}" for m in docs]
    documents = [f"Tool: {m.name}\nSource: {m.source}\n\n{m.text}" for m in docs]
    metadatas = [
        {
            "name": m.name,
            "source": m.source,
            "binary_path": m.binary_path or "",
            "platform": platform.system().lower(),
        }
        for m in docs
    ]
    upserted = store.upsert_documents(
        collection=WorkspaceVectorStore.TOOLS_COLLECTION,
        ids=ids,
        documents=documents,
        metadatas=metadatas,
    )
    live_count = sum(1 for m in docs if m.source == "live")
    seed_count = sum(1 for m in docs if m.source == "seed")
    skipped = len(set(n.lower() for n in KALI_TOOL_CATALOG)) - len(docs)
    report = IndexReport(
        platform=platform.platform(),
        live_count=live_count,
        seed_count=seed_count,
        skipped=max(0, skipped),
        total_upserted=upserted,
        collection_size=store.count(WorkspaceVectorStore.TOOLS_COLLECTION),
        tools=tuple(m.name for m in docs),
    )
    logger.info(
        "indexed tools live=%s seed=%s total=%s platform=%s",
        report.live_count,
        report.seed_count,
        report.total_upserted,
        report.platform,
    )
    return report


def search_kali_tools(
    query: str,
    *,
    store: WorkspaceVectorStore,
    n_results: int = 5,
) -> str:
    """
    Search the workspace tool-manual vector DB for Kali tools matching ``query``.

    Returns a formatted string the orchestrator can use to build
    ``execute_kali_command`` invocations.
    """
    q = query.strip()
    if not q:
        raise ValueError(f"{TOOL_NAME} requires a non-empty query")

    hits = store.search(
        collection=WorkspaceVectorStore.TOOLS_COLLECTION,
        query=q,
        n_results=n_results,
    )
    if not hits:
        return (
            "No tool manuals indexed yet. Run `potocus tools index` in this workspace "
            "(on Kali use `--live-only` after install for full coverage)."
        )

    blocks: list[str] = [f"search_kali_tools query={q!r} results={len(hits)}"]
    for i, hit in enumerate(hits, start=1):
        name = hit.metadata.get("name", hit.id)
        source = hit.metadata.get("source", "?")
        dist = f"{hit.distance:.4f}" if hit.distance is not None else "n/a"
        # Keep each hit bounded so the orchestrator context stays healthy.
        snippet = hit.document.strip()
        if len(snippet) > 2500:
            snippet = snippet[:2500] + "\n… [truncated]"
        blocks.append(
            f"--- result {i}: {name} (source={source}, distance={dist}) ---\n{snippet}"
        )
    return "\n\n".join(blocks)
