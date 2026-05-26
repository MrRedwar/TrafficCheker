# -*- coding: utf-8 -*-
from __future__ import annotations

import csv
import ctypes
import ipaddress
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable


MAX_INTERFACE_NAME_LEN = 256
MAXLEN_IFDESCR = 256
MAXLEN_PHYSADDR = 8
URLHAUS_HOSTFILE_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"
URLHAUS_HOST_SET: set[str] | None = None
URLHAUS_HOST_ERROR = ""
VIRUSTOTAL_API_KEY_ENV = "VT_API_KEY"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
LOCAL_CONFIG_PATH = Path(__file__).with_name("traffic_checker.local.json")


class MibIfRow(ctypes.Structure):
    _fields_ = [
        ("wszName", ctypes.c_wchar * MAX_INTERFACE_NAME_LEN),
        ("dwIndex", ctypes.c_ulong),
        ("dwType", ctypes.c_ulong),
        ("dwMtu", ctypes.c_ulong),
        ("dwSpeed", ctypes.c_ulong),
        ("dwPhysAddrLen", ctypes.c_ulong),
        ("bPhysAddr", ctypes.c_ubyte * MAXLEN_PHYSADDR),
        ("dwAdminStatus", ctypes.c_ulong),
        ("dwOperStatus", ctypes.c_ulong),
        ("dwLastChange", ctypes.c_ulong),
        ("dwInOctets", ctypes.c_ulong),
        ("dwInUcastPkts", ctypes.c_ulong),
        ("dwInNUcastPkts", ctypes.c_ulong),
        ("dwInDiscards", ctypes.c_ulong),
        ("dwInErrors", ctypes.c_ulong),
        ("dwInUnknownProtos", ctypes.c_ulong),
        ("dwOutOctets", ctypes.c_ulong),
        ("dwOutUcastPkts", ctypes.c_ulong),
        ("dwOutNUcastPkts", ctypes.c_ulong),
        ("dwOutDiscards", ctypes.c_ulong),
        ("dwOutErrors", ctypes.c_ulong),
        ("dwOutQLen", ctypes.c_ulong),
        ("dwDescrLen", ctypes.c_ulong),
        ("bDescr", ctypes.c_ubyte * MAXLEN_IFDESCR),
    ]


@dataclass(frozen=True)
class AdapterStat:
    name: str
    status: str
    received_bytes: int
    sent_bytes: int


@dataclass
class Connection:
    proto: str
    local: str
    remote: str
    state: str
    pid: str
    process: str
    remote_port: str
    observed_at: datetime
    last_seen_at: datetime | None = None
    seen_count: int = 1

    @property
    def key(self) -> str:
        return f"{self.proto}|{self.local}|{self.remote}|{self.state}|{self.pid}"

    def touch(self, observed_at: datetime) -> None:
        self.last_seen_at = observed_at
        self.seen_count += 1

    @property
    def last_seen(self) -> datetime:
        return self.last_seen_at or self.observed_at


@dataclass
class CaptureState:
    started_at: datetime | None = None
    adapter_start: list[AdapterStat] = field(default_factory=list)
    connections: dict[str, Connection] = field(default_factory=dict)
    samples: int = 0


def run_command(args: list[str]) -> str:
    completed = subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        check=False,
    )
    return completed.stdout


def run_command_oem(args: list[str]) -> str:
    completed = subprocess.run(
        args,
        capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        check=False,
    )
    return completed.stdout.decode("oem", errors="replace")


def clean_domain(value: str) -> str:
    value = value.strip().strip(".").lower()
    if not value or " " in value:
        return ""
    return value


def load_local_config() -> dict[str, str]:
    if not LOCAL_CONFIG_PATH.exists():
        return {}
    try:
        with LOCAL_CONFIG_PATH.open("r", encoding="utf-8") as file:
            payload = json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {str(key): str(value).strip() for key, value in payload.items() if value}


def get_virustotal_api_key() -> str:
    env_key = os.environ.get(VIRUSTOTAL_API_KEY_ENV, "").strip()
    if env_key:
        return env_key
    config = load_local_config()
    return config.get("virustotal_api_key", "") or config.get(VIRUSTOTAL_API_KEY_ENV, "")


def build_dns_cache() -> dict[str, set[str]]:
    if sys.platform != "win32":
        return {}

    output = run_command_oem(["ipconfig", "/displaydns"])
    cache: dict[str, set[str]] = {}
    current_name = ""

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if ("Record Name" in line or "Имя записи" in line) and ":" in line:
            current_name = clean_domain(line.split(":", 1)[1])
            continue

        if (
            "A (Host) Record" in line
            or "AAAA Record" in line
            or "А-запись" in line
            or "AAAA-запись" in line
        ) and ":" in line and current_name:
            address = line.split(":", 1)[1].strip()
            try:
                ipaddress.ip_address(address)
            except ValueError:
                continue
            cache.setdefault(address, set()).add(current_name)

    return cache


def decode_adapter_description(row: MibIfRow) -> str:
    length = min(int(row.dwDescrLen), MAXLEN_IFDESCR)
    raw = bytes(row.bDescr[:length])
    return raw.decode("mbcs", errors="replace").strip("\x00").strip()


def get_adapter_stats() -> list[AdapterStat]:
    if sys.platform != "win32":
        rows: list[AdapterStat] = []
        net_dir = Path("/sys/class/net")
        if not net_dir.exists():
            return rows
        for interface in sorted(net_dir.iterdir()):
            try:
                received = int((interface / "statistics" / "rx_bytes").read_text(encoding="utf-8").strip())
                sent = int((interface / "statistics" / "tx_bytes").read_text(encoding="utf-8").strip())
                state = (interface / "operstate").read_text(encoding="utf-8").strip()
            except (OSError, ValueError):
                continue
            rows.append(
                AdapterStat(
                    name=interface.name,
                    status="Up" if state == "up" else "Down",
                    received_bytes=received,
                    sent_bytes=sent,
                )
            )
        return rows

    iphlpapi = ctypes.windll.iphlpapi
    get_if_table = iphlpapi.GetIfTable
    get_if_table.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_bool]
    get_if_table.restype = ctypes.c_ulong

    size = ctypes.c_ulong(0)
    get_if_table(None, ctypes.byref(size), False)
    buffer = ctypes.create_string_buffer(size.value)
    result = get_if_table(buffer, ctypes.byref(size), False)
    if result != 0:
        return []

    count = ctypes.c_ulong.from_buffer(buffer).value
    offset = ctypes.sizeof(ctypes.c_ulong)
    row_size = ctypes.sizeof(MibIfRow)
    rows: list[AdapterStat] = []

    for index in range(count):
        row = MibIfRow.from_buffer_copy(buffer, offset + index * row_size)
        name = decode_adapter_description(row) or row.wszName or f"Interface {row.dwIndex}"
        status = "Up" if row.dwOperStatus == 5 else "Down"
        rows.append(
            AdapterStat(
                name=name,
                status=status,
                received_bytes=int(row.dwInOctets),
                sent_bytes=int(row.dwOutOctets),
            )
        )

    return rows


def get_process_map() -> dict[str, str]:
    if sys.platform != "win32":
        return {}

    output = run_command(["tasklist", "/fo", "csv", "/nh"])
    processes: dict[str, str] = {}
    for row in csv.reader(output.splitlines()):
        if len(row) >= 2:
            if row[1] == "0":
                continue
            name = row[0].removesuffix(".exe")
            processes[row[1]] = name
    return processes


def get_port(endpoint: str) -> str:
    if endpoint == "*:*":
        return "*"
    if endpoint.startswith("["):
        closing = endpoint.rfind("]")
        if closing >= 0:
            rest = endpoint[closing + 1 :]
            return rest[1:] if rest.startswith(":") else ""
    if ":" not in endpoint:
        return ""
    return endpoint.rsplit(":", 1)[1]


def get_endpoint_host(endpoint: str) -> str:
    if not endpoint or endpoint == "*:*":
        return ""
    if endpoint.startswith("["):
        closing = endpoint.rfind("]")
        if closing >= 0:
            return endpoint[1:closing]
    if ":" not in endpoint:
        return endpoint
    return endpoint.rsplit(":", 1)[0]


def is_local_or_private_host(host: str) -> bool:
    if not host or host in {"*", "localhost", "0.0.0.0", "::"}:
        return True
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    return (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    )


def is_external_connection(connection: Connection) -> bool:
    return not is_local_or_private_host(get_endpoint_host(connection.remote))


def site_for_connection(connection: Connection, dns_cache: dict[str, set[str]] | None = None) -> str:
    host = get_endpoint_host(connection.remote)
    if not host or is_local_or_private_host(host):
        return "(локально/служебно)"

    names = sorted((dns_cache or {}).get(host, set()))
    if names:
        return sorted(names, key=lambda value: (len(value), value))[0]

    return host


def rdap_owner_from_payload(payload: dict[str, object]) -> str:
    candidates: list[str] = []

    for key in ("name", "handle"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip())

    for entity in payload.get("entities", []) or []:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles", []) or []
        if roles and not any(role in roles for role in ("registrant", "administrative", "technical")):
            continue
        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
            continue
        for field in vcard[1]:
            if not isinstance(field, list) or len(field) < 4:
                continue
            if field[0] in ("org", "fn") and isinstance(field[3], str) and field[3].strip():
                candidates.append(field[3].strip())

    for candidate in candidates:
        if candidate and not candidate.upper().startswith(("NET-", "RIPE-", "APNIC-")):
            return candidate
    return candidates[0] if candidates else ""


def lookup_ip_owner(ip_value: str, owner_cache: dict[str, str], timeout: float = 1.5) -> str:
    if not ip_value or is_local_or_private_host(ip_value):
        return ""
    if ip_value in owner_cache:
        return owner_cache[ip_value]

    request = urllib.request.Request(
        f"https://rdap.org/ip/{ip_value}",
        headers={"User-Agent": "TrafficChecker/0.1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        owner_cache[ip_value] = ""
        return ""

    owner = rdap_owner_from_payload(payload)
    owner_cache[ip_value] = owner
    return owner


def load_urlhaus_host_set(timeout: float = 12.0) -> tuple[set[str], str]:
    global URLHAUS_HOST_SET, URLHAUS_HOST_ERROR

    if URLHAUS_HOST_SET is not None:
        return URLHAUS_HOST_SET, URLHAUS_HOST_ERROR

    request = urllib.request.Request(
        URLHAUS_HOSTFILE_URL,
        headers={"User-Agent": "TrafficChecker/0.1"},
    )
    hosts: set[str] = set()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError, TimeoutError):
        URLHAUS_HOST_SET = set()
        URLHAUS_HOST_ERROR = "URLhaus hostfile недоступен"
        return URLHAUS_HOST_SET, URLHAUS_HOST_ERROR

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        candidate = parts[-1] if parts else ""
        candidate = clean_domain(candidate)
        if candidate and candidate not in {"localhost", "0.0.0.0"}:
            hosts.add(candidate)

    URLHAUS_HOST_SET = hosts
    URLHAUS_HOST_ERROR = ""
    return hosts, ""


def host_matches_urlhaus(host: str, malicious_hosts: set[str]) -> bool:
    host = clean_domain(host)
    if not host:
        return False
    if host in malicious_hosts:
        return True

    labels = host.split(".")
    for index in range(1, max(1, len(labels) - 1)):
        parent = ".".join(labels[index:])
        if parent in malicious_hosts:
            return True
    return False


def lookup_urlhaus_host(host: str, threat_cache: dict[str, dict[str, str]], timeout: float = 12.0) -> dict[str, str]:
    host = clean_domain(host)
    if not host or host in threat_cache or host == "(локально/служебно)":
        return threat_cache.get(host, {})

    malicious_hosts, error = load_urlhaus_host_set(timeout=timeout)
    if error:
        result = {
            "safety": "Не проверено",
            "risk_rating": "Неизвестно",
            "threat_source": error,
            "threat_details": "",
        }
        threat_cache[host] = result
        return result

    if host_matches_urlhaus(host, malicious_hosts):
        safety = "Опасно"
        risk_rating = "Высокий риск"
        details = "URLhaus hostfile: хост найден в списке malware hosts"
    else:
        safety = "Не найдено в базе угроз"
        risk_rating = "Низкий риск"
        details = "URLhaus hostfile: совпадений нет"

    result = {
        "safety": safety,
        "risk_rating": risk_rating,
        "threat_source": "URLhaus hostfile",
        "threat_details": details,
    }
    threat_cache[host] = result
    return result


def virustotal_endpoint_for_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        kind = "domains"
    else:
        kind = "ip_addresses"
    return f"{VIRUSTOTAL_API_URL}/{kind}/{urllib.parse.quote(host, safe='')}"


def classify_virustotal_stats(malicious: int, suspicious: int, harmless: int, undetected: int) -> tuple[str, str]:
    detections = malicious + suspicious
    checked = detections + harmless + undetected

    if malicious >= 3 or detections >= 5:
        return "Опасно", "Высокий риск"
    if malicious > 0:
        if malicious == 1 and suspicious == 0 and harmless >= 10:
            return "Подозрительно", "Низкий риск"
        return "Подозрительно", "Средний риск"
    if suspicious > 0:
        if suspicious == 1 and harmless >= 10:
            return "Подозрительно", "Низкий риск"
        return "Подозрительно", "Средний риск"
    if checked > 0:
        return "Не найдено в базе угроз", "Низкий риск"
    return "Не проверено", "Неизвестно"


def lookup_virustotal_host(host: str, timeout: float = 8.0) -> dict[str, str]:
    api_key = get_virustotal_api_key()
    if not api_key:
        return {
            "safety": "",
            "risk_rating": "",
            "threat_source": "",
            "threat_details": "VirusTotal: не настроен VT_API_KEY",
            "vt_checked": "no_key",
        }

    request = urllib.request.Request(
        virustotal_endpoint_for_host(host),
        headers={
            "User-Agent": "TrafficChecker/0.1",
            "x-apikey": api_key,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        return {
            "safety": "Не проверено",
            "risk_rating": "Неизвестно",
            "threat_source": "VirusTotal",
            "threat_details": f"VirusTotal: HTTP {exc.code}",
            "vt_checked": "error",
        }
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return {
            "safety": "Не проверено",
            "risk_rating": "Неизвестно",
            "threat_source": "VirusTotal",
            "threat_details": "VirusTotal: не удалось получить ответ",
            "vt_checked": "error",
        }

    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {}) if isinstance(attributes, dict) else {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    safety, risk_rating = classify_virustotal_stats(malicious, suspicious, harmless, undetected)
    detections = malicious + suspicious

    return {
        "safety": safety,
        "risk_rating": risk_rating,
        "threat_source": "VirusTotal",
        "threat_details": (
            "VirusTotal: "
            f"срабатываний {detections} (malicious {malicious}, suspicious {suspicious}), "
            f"безопасных отметок {harmless}, без результата {undetected}"
        ),
        "vt_checked": "yes",
        "vt_malicious": str(malicious),
        "vt_suspicious": str(suspicious),
        "vt_harmless": str(harmless),
        "vt_undetected": str(undetected),
    }


def merge_reputation(base: dict[str, str], extra: dict[str, str]) -> dict[str, str]:
    severity = {
        "Опасно": 5,
        "Подозрительно": 4,
        "Не проверено": 3,
        "Ожидает проверки": 2,
        "Не найдено в базе угроз": 1,
        "": 0,
    }
    sources = [value for value in (base.get("threat_source", ""), extra.get("threat_source", "")) if value]
    details = [value for value in (base.get("threat_details", ""), extra.get("threat_details", "")) if value]
    safety = base.get("safety", "")
    if severity.get(extra.get("safety", ""), 0) > severity.get(safety, 0):
        safety = extra.get("safety", "")

    risk_severity = {
        "Высокий риск": 3,
        "Средний риск": 2,
        "Низкий риск": 1,
        "Неизвестно": 0,
        "": 0,
    }
    risk_rating = base.get("risk_rating", "")
    if risk_severity.get(extra.get("risk_rating", ""), 0) > risk_severity.get(risk_rating, 0):
        risk_rating = extra.get("risk_rating", "")

    return {
        "safety": safety,
        "risk_rating": risk_rating,
        "threat_source": "; ".join(dict.fromkeys(sources)),
        "threat_details": "; ".join(details),
        "vt_checked": extra.get("vt_checked", base.get("vt_checked", "")),
        "vt_malicious": extra.get("vt_malicious", base.get("vt_malicious", "")),
        "vt_suspicious": extra.get("vt_suspicious", base.get("vt_suspicious", "")),
        "vt_harmless": extra.get("vt_harmless", base.get("vt_harmless", "")),
        "vt_undetected": extra.get("vt_undetected", base.get("vt_undetected", "")),
    }


def lookup_host_reputation(
    host: str,
    threat_cache: dict[str, dict[str, str]],
    include_virustotal: bool = True,
) -> dict[str, str]:
    host = clean_domain(host)
    if not host or host == "(локально/служебно)":
        return {}

    current = threat_cache.get(host)
    if current and (not include_virustotal or current.get("vt_checked") in {"yes", "no_key", "error"}):
        return current

    result = current or lookup_urlhaus_host(host, threat_cache, timeout=2.5)
    if include_virustotal:
        result = merge_reputation(result, lookup_virustotal_host(host, timeout=8.0))

    threat_cache[host] = result
    return result


def collect_ip_owners(
    connections: list[Connection],
    owner_cache: dict[str, str],
    limit: int = 8,
) -> dict[str, str]:
    updates: dict[str, str] = {}
    checked = 0
    for connection in connections:
        if checked >= limit:
            break
        if not is_external_connection(connection):
            continue
        host = get_endpoint_host(connection.remote)
        if not host or host in owner_cache:
            continue
        updates[host] = lookup_ip_owner(host, owner_cache)
        checked += 1
    return updates


def collect_host_reputation(
    connections: list[Connection],
    dns_cache: dict[str, set[str]] | None,
    threat_cache: dict[str, dict[str, str]],
    limit: int = 6,
    virustotal_limit: int = 10,
) -> dict[str, dict[str, str]]:
    updates: dict[str, dict[str, str]] = {}
    checked = 0
    vt_checked = 0
    for connection in connections:
        if checked >= limit:
            break
        if not is_external_connection(connection):
            continue
        site = site_for_connection(connection, dns_cache)
        host = site.split(",", 1)[0].strip()
        cached = threat_cache.get(host)
        if not host or (cached and cached.get("vt_checked") in {"yes", "no_key", "error"}):
            continue
        include_virustotal = vt_checked < virustotal_limit
        updates[host] = lookup_host_reputation(host, threat_cache, include_virustotal=include_virustotal)
        if include_virustotal:
            vt_checked += 1
        checked += 1
    return updates


def owner_for_connection(connection: Connection, owner_cache: dict[str, str] | None = None) -> str:
    host = get_endpoint_host(connection.remote)
    if not host or is_local_or_private_host(host):
        return ""
    return (owner_cache or {}).get(host, "")


def reputation_for_connection(
    connection: Connection,
    dns_cache: dict[str, set[str]] | None = None,
    threat_cache: dict[str, dict[str, str]] | None = None,
) -> dict[str, str]:
    site = site_for_connection(connection, dns_cache)
    host = site.split(",", 1)[0].strip()
    if not host or host == "(локально/служебно)":
        return {"safety": "", "risk_rating": "", "threat_source": "", "threat_details": ""}
    return (threat_cache or {}).get(
        host,
        {
            "safety": "Ожидает проверки",
            "risk_rating": "Ожидает проверки",
            "threat_source": "URLhaus",
            "threat_details": "",
        },
    )


def merge_connection(target: dict[str, Connection], connection: Connection) -> None:
    existing = target.get(connection.key)
    if existing:
        existing.touch(connection.observed_at)
        return
    target[connection.key] = connection


def parse_ss_process(value: str) -> tuple[str, str]:
    pid_match = re.search(r"pid=(\d+)", value)
    name_match = re.search(r'\(\("([^"]+)"', value)
    pid = pid_match.group(1) if pid_match else ""
    process = name_match.group(1) if name_match else ""
    return pid, process


def get_ss_snapshot() -> list[Connection]:
    output = run_command(["ss", "-tunapH"])
    now = datetime.now()
    rows: list[Connection] = []

    for raw_line in output.splitlines():
        parts = raw_line.split(maxsplit=5)
        if len(parts) < 5:
            continue

        proto = parts[0].upper()
        if proto not in {"TCP", "UDP"}:
            continue

        state = parts[1] if len(parts) > 1 else "OPEN"
        local = parts[4]
        remote = parts[5].split(maxsplit=1)[0] if len(parts) > 5 else "*:*"
        details = parts[5] if len(parts) > 5 else ""
        pid, process = parse_ss_process(details)

        rows.append(
            Connection(
                proto=proto,
                local=local,
                remote=remote,
                state=state,
                pid=pid,
                process=process,
                remote_port=get_port(remote),
                observed_at=now,
            )
        )

    return rows


def get_netstat_snapshot() -> list[Connection]:
    if sys.platform != "win32":
        return get_ss_snapshot()

    processes = get_process_map()
    output = run_command(["netstat", "-ano"])
    now = datetime.now()
    rows: list[Connection] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not (line.startswith("TCP ") or line.startswith("UDP ")):
            continue

        parts = line.split()
        if parts[0] == "TCP" and len(parts) >= 5:
            pid = parts[4]
            rows.append(
                Connection(
                    proto=parts[0],
                    local=parts[1],
                    remote=parts[2],
                    state=parts[3],
                    pid=pid,
                    process=processes.get(pid, "(сессия закрыта)" if pid == "0" else ""),
                    remote_port=get_port(parts[2]),
                    observed_at=now,
                )
            )
        elif parts[0] == "UDP" and len(parts) >= 4:
            pid = parts[3]
            rows.append(
                Connection(
                    proto=parts[0],
                    local=parts[1],
                    remote=parts[2],
                    state="OPEN",
                    pid=pid,
                    process=processes.get(pid, "(сессия закрыта)" if pid == "0" else ""),
                    remote_port=get_port(parts[2]),
                    observed_at=now,
                )
            )

    return rows


def format_size(value: int) -> str:
    value = max(0, int(value))
    if value >= 1024**3:
        return f"{value / 1024**3:.2f} ГБ"
    if value >= 1024**2:
        return f"{value / 1024**2:.2f} МБ"
    if value >= 1024:
        return f"{value / 1024:.2f} КБ"
    return f"{value} Б"


def group_count(items: Iterable[object], attr: str, limit: int = 100) -> list[dict[str, object]]:
    counter = Counter(getattr(item, attr, "") or "(неизвестно)" for item in items)
    return [{"name": name, "count": count} for name, count in counter.most_common(limit)]


def build_adapter_rows(start_rows: list[AdapterStat], end_rows: list[AdapterStat]) -> list[dict[str, object]]:
    end_by_name = {row.name: row for row in end_rows}
    rows: list[dict[str, object]] = []

    for start in start_rows:
        end = end_by_name.get(start.name)
        if not end:
            continue
        received = max(0, end.received_bytes - start.received_bytes)
        sent = max(0, end.sent_bytes - start.sent_bytes)
        if received == 0 and sent == 0:
            continue
        rows.append(
            {
                "adapter": start.name,
                "status": end.status,
                "received": format_size(received),
                "sent": format_size(sent),
                "total": format_size(received + sent),
                "received_bytes": received,
                "sent_bytes": sent,
            }
        )

    rows.sort(key=lambda row: row["received_bytes"] + row["sent_bytes"], reverse=True)
    return rows


def build_analysis_rows(
    connections: list[Connection],
    adapter_rows: list[dict[str, object]],
    dns_cache: dict[str, set[str]] | None = None,
    owner_cache: dict[str, str] | None = None,
    threat_cache: dict[str, dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    external = [c for c in connections if is_external_connection(c)]
    internal = [c for c in connections if not is_external_connection(c)]
    external_established = [c for c in external if c.state == "ESTABLISHED"]
    external_waiting = [c for c in external if c.state in {"TIME_WAIT", "CLOSE_WAIT"}]
    external_udp = [c for c in external if c.proto == "UDP"]

    def add(level: str, finding: str, details: str) -> None:
        rows.append({"level": level, "finding": finding, "details": details})

    add(
        "Инфо",
        "Область сбора",
        (
            f"Наблюдено {len(connections)} уникальных сессий: "
            f"{len(external)} внешних и {len(internal)} внутренних/служебных. "
            "Дальнейший анализ сфокусирован на внешнем трафике."
        ),
    )

    if adapter_rows:
        top = adapter_rows[0]
        add(
            "Инфо",
            "Основной сетевой адаптер",
            f"{top['adapter']}: получено {top['received']}, отправлено {top['sent']}, всего {top['total']}.",
        )
    else:
        add("Заметка", "Нет прироста трафика по адаптерам", "Счетчики интерфейсов пока не изменились.")

    if external:
        add(
            "Инфо",
            "Внешний трафик",
            (
                f"{len(external)} внешних сессий: {len(external_established)} активных TCP, "
                f"{len(external_udp)} UDP/открытых, {len(external_waiting)} ожидающих закрытия."
            ),
        )
    else:
        add("Норма", "Внешний трафик не обнаружен", "Во время анализа публичные удаленные адреса не появлялись.")

    top_processes = group_count(external, "process", 5)
    if top_processes:
        add("Инфо", "Самые заметные внешние процессы", ", ".join(f"{r['name']} ({r['count']})" for r in top_processes))

    top_sites = site_rows(external, dns_cache=dns_cache, owner_cache=owner_cache, external_only=True, limit=5)
    if top_sites:
        add("Инфо", "Самые заметные сайты/домены", ", ".join(f"{r['site']} ({r['sessions']})" for r in top_sites))

    top_owners = owner_rows(external, owner_cache=owner_cache, limit=5)
    if top_owners:
        add("Инфо", "Владельцы IP-диапазонов", ", ".join(f"{r['owner']} ({r['sessions']})" for r in top_owners))

    reputation = reputation_rows(external, dns_cache=dns_cache, threat_cache=threat_cache, limit=5)
    bad_reputation = [row for row in reputation if row["safety"] in {"Опасно", "Подозрительно"}]
    pending_reputation = [row for row in reputation if row["safety"] in {"Ожидает проверки", "Не проверено"}]
    if bad_reputation:
        add("Проверить", "Есть совпадения с базой угроз", ", ".join(f"{r['site']}: {r['safety']} / {r['risk_rating']}" for r in bad_reputation[:5]))
    elif reputation and not pending_reputation:
        add("Норма", "Совпадений с базами угроз не найдено", "Проверенные сайты/IP не найдены в подключенных источниках репутации.")
    elif pending_reputation:
        add("Заметка", "Проверка репутации еще идет", f"Ожидают проверки: {len(pending_reputation)} записей.")

    external_ports = group_count(external, "remote_port", 5)
    if external_ports:
        port_text = ", ".join(f"{r['name']} ({r['count']})" for r in external_ports)
        common_port_count = sum(1 for item in external if item.remote_port in {"80", "443", "53", "123"})
        common_ratio = common_port_count / len(external) if external else 0
        if common_ratio >= 0.9:
            add("Норма", "Внешние порты выглядят типично", f"{common_port_count} из {len(external)} внешних сессий идут через web/DNS/time-порты. Топ: {port_text}.")
        else:
            add("Внимание", "Есть заметная доля нетипичных портов", port_text)

    close_wait = [c for c in external if c.state == "CLOSE_WAIT"]
    if close_wait:
        processes = ", ".join(f"{r['name']} ({r['count']})" for r in group_count(close_wait, "process", 5))
        add(
            "Проверить",
            "Сокеты CLOSE_WAIT",
            f"{len(close_wait)} внешних сессий ожидают закрытия локальным приложением. Процессы: {processes}.",
        )

    if len(external_waiting) > 30:
        add(
            "Внимание",
            "Много коротких соединений",
            f"{len(external_waiting)} внешних сессий находятся в TIME_WAIT/CLOSE_WAIT. Это часто бывает у браузеров и мессенджеров.",
        )

    non_web = [c for c in external if c.remote_port not in {"80", "443", "53", "123", "*", "0"}]
    if non_web:
        ports = ", ".join(f"{r['name']} ({r['count']})" for r in group_count(non_web, "remote_port", 5))
        add("Проверить", "Нестандартные внешние порты", f"{len(non_web)} сокетов используют порты: {ports}.")
    elif external:
        add("Норма", "Нестандартные внешние порты не найдены", "Во внешних сессиях видны только типичные web/DNS/time-порты.")

    unknown = [c for c in external if not c.process]
    if unknown:
        add(
            "Заметка",
            "Неизвестные процессы",
            f"{len(unknown)} внешних сессий не удалось связать с процессом. Возможно, процесс завершился во время сбора.",
        )

    return rows


def connection_rows(
    connections: list[Connection],
    external_only: bool = False,
    dns_cache: dict[str, set[str]] | None = None,
    owner_cache: dict[str, str] | None = None,
    threat_cache: dict[str, dict[str, str]] | None = None,
) -> list[dict[str, object]]:
    visible_connections = [item for item in connections if is_external_connection(item)] if external_only else connections
    return [
        {
            "first_seen": item.observed_at.strftime("%H:%M:%S"),
            "last_seen": item.last_seen.strftime("%H:%M:%S"),
            "seen_count": item.seen_count,
            "site": site_for_connection(item, dns_cache),
            "owner": owner_for_connection(item, owner_cache),
            "safety": reputation_for_connection(item, dns_cache, threat_cache).get("safety", ""),
            "risk_rating": reputation_for_connection(item, dns_cache, threat_cache).get("risk_rating", ""),
            "proto": item.proto,
            "local": item.local,
            "remote": item.remote,
            "state": item.state,
            "pid": item.pid,
            "process": item.process,
        }
        for item in sorted(visible_connections, key=lambda row: row.last_seen, reverse=True)
    ]


def site_rows(
    connections: list[Connection],
    dns_cache: dict[str, set[str]] | None = None,
    owner_cache: dict[str, str] | None = None,
    threat_cache: dict[str, dict[str, str]] | None = None,
    external_only: bool = False,
    limit: int = 100,
) -> list[dict[str, object]]:
    visible_connections = [item for item in connections if is_external_connection(item)] if external_only else connections
    grouped: dict[tuple[str, str, str], dict[str, object]] = {}

    for item in visible_connections:
        host = get_endpoint_host(item.remote)
        site = site_for_connection(item, dns_cache)
        key = (site, item.process or "(неизвестно)", item.remote_port)
        row = grouped.setdefault(
            key,
            {
                "site": site,
                "process": item.process or "(неизвестно)",
                "remote_port": item.remote_port,
                "owner": owner_for_connection(item, owner_cache),
                "safety": reputation_for_connection(item, dns_cache, threat_cache).get("safety", ""),
                "risk_rating": reputation_for_connection(item, dns_cache, threat_cache).get("risk_rating", ""),
                "sessions": 0,
                "first_seen": item.observed_at,
                "last_seen": item.last_seen,
                "ips": set(),
            },
        )
        row["sessions"] = int(row["sessions"]) + 1
        row["first_seen"] = min(row["first_seen"], item.observed_at)
        row["last_seen"] = max(row["last_seen"], item.last_seen)
        if host:
            row["ips"].add(host)

    rows = []
    for row in grouped.values():
        rows.append(
            {
                "site": row["site"],
                "process": row["process"],
                "remote_port": row["remote_port"],
                "owner": row["owner"],
                "safety": row["safety"],
                "risk_rating": row["risk_rating"],
                "sessions": row["sessions"],
                "first_seen": row["first_seen"].strftime("%H:%M:%S"),
                "last_seen": row["last_seen"].strftime("%H:%M:%S"),
                "ips": ", ".join(sorted(row["ips"])[:5]),
            }
        )

    rows.sort(key=lambda item: (int(item["sessions"]), item["last_seen"]), reverse=True)
    return rows[:limit]


def owner_rows(
    connections: list[Connection],
    owner_cache: dict[str, str] | None = None,
    limit: int = 100,
) -> list[dict[str, object]]:
    grouped: dict[str, dict[str, object]] = {}
    for item in connections:
        owner = owner_for_connection(item, owner_cache) or "(владелец не определен)"
        host = get_endpoint_host(item.remote)
        row = grouped.setdefault(
            owner,
            {
                "owner": owner,
                "sessions": 0,
                "first_seen": item.observed_at,
                "last_seen": item.last_seen,
                "ips": set(),
            },
        )
        row["sessions"] = int(row["sessions"]) + 1
        row["first_seen"] = min(row["first_seen"], item.observed_at)
        row["last_seen"] = max(row["last_seen"], item.last_seen)
        if host:
            row["ips"].add(host)

    rows = []
    for row in grouped.values():
        rows.append(
            {
                "owner": row["owner"],
                "sessions": row["sessions"],
                "first_seen": row["first_seen"].strftime("%H:%M:%S"),
                "last_seen": row["last_seen"].strftime("%H:%M:%S"),
                "ips": ", ".join(sorted(row["ips"])[:8]),
            }
        )
    rows.sort(key=lambda item: (int(item["sessions"]), item["last_seen"]), reverse=True)
    return rows[:limit]


def reputation_rows(
    connections: list[Connection],
    dns_cache: dict[str, set[str]] | None = None,
    threat_cache: dict[str, dict[str, str]] | None = None,
    limit: int = 100,
) -> list[dict[str, object]]:
    grouped: dict[str, dict[str, object]] = {}
    for item in connections:
        site = site_for_connection(item, dns_cache)
        reputation = reputation_for_connection(item, dns_cache, threat_cache)
        row = grouped.setdefault(
            site,
            {
                "site": site,
                "safety": reputation.get("safety", ""),
                "risk_rating": reputation.get("risk_rating", ""),
                "threat_source": reputation.get("threat_source", ""),
                "threat_details": reputation.get("threat_details", ""),
                "sessions": 0,
                "first_seen": item.observed_at,
                "last_seen": item.last_seen,
            },
        )
        row["sessions"] = int(row["sessions"]) + 1
        row["first_seen"] = min(row["first_seen"], item.observed_at)
        row["last_seen"] = max(row["last_seen"], item.last_seen)
        if reputation.get("safety") in {"Опасно", "Подозрительно"}:
            row["safety"] = reputation.get("safety", "")
            row["risk_rating"] = reputation.get("risk_rating", "")
            row["threat_source"] = reputation.get("threat_source", "")
            row["threat_details"] = reputation.get("threat_details", "")

    severity = {
        "Опасно": 5,
        "Подозрительно": 4,
        "Не проверено": 3,
        "Ожидает проверки": 2,
        "Не найдено в базе угроз": 1,
        "": 0,
    }
    rows = []
    for row in grouped.values():
        rows.append(
            {
                "site": row["site"],
                "safety": row["safety"],
                "risk_rating": row["risk_rating"],
                "threat_source": row["threat_source"],
                "threat_details": row["threat_details"],
                "sessions": row["sessions"],
                "first_seen": row["first_seen"].strftime("%H:%M:%S"),
                "last_seen": row["last_seen"].strftime("%H:%M:%S"),
            }
        )
    risk_severity = {"Высокий риск": 3, "Средний риск": 2, "Низкий риск": 1, "Неизвестно": 0, "Ожидает проверки": 0, "": 0}
    rows.sort(key=lambda item: (severity.get(str(item["safety"]), 0), risk_severity.get(str(item["risk_rating"]), 0), int(item["sessions"])), reverse=True)
    return rows[:limit]


def save_connections_csv(
    path: str,
    connections: Iterable[Connection],
    dns_cache: dict[str, set[str]] | None = None,
    owner_cache: dict[str, str] | None = None,
    threat_cache: dict[str, dict[str, str]] | None = None,
) -> None:
    fieldnames = ["first_seen", "last_seen", "seen_count", "site", "owner", "safety", "risk_rating", "proto", "local", "remote", "state", "pid", "process", "remote_port"]
    with open(path, "w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for item in sorted(connections, key=lambda row: row.last_seen, reverse=True):
            writer.writerow(
                {
                    "first_seen": item.observed_at.isoformat(timespec="seconds"),
                    "last_seen": item.last_seen.isoformat(timespec="seconds"),
                    "seen_count": item.seen_count,
                    "site": site_for_connection(item, dns_cache),
                    "owner": owner_for_connection(item, owner_cache),
                    "safety": reputation_for_connection(item, dns_cache, threat_cache).get("safety", ""),
                    "risk_rating": reputation_for_connection(item, dns_cache, threat_cache).get("risk_rating", ""),
                    "proto": item.proto,
                    "local": item.local,
                    "remote": item.remote,
                    "state": item.state,
                    "pid": item.pid,
                    "process": item.process,
                    "remote_port": item.remote_port,
                }
            )
