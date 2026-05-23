# -*- coding: utf-8 -*-
from __future__ import annotations

import csv
import ctypes
import ipaddress
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable


MAX_INTERFACE_NAME_LEN = 256
MAXLEN_IFDESCR = 256
MAXLEN_PHYSADDR = 8


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


@dataclass(frozen=True)
class Connection:
    proto: str
    local: str
    remote: str
    state: str
    pid: str
    process: str
    remote_port: str
    observed_at: datetime

    @property
    def key(self) -> str:
        return f"{self.proto}|{self.local}|{self.remote}|{self.state}|{self.pid}"


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


def decode_adapter_description(row: MibIfRow) -> str:
    length = min(int(row.dwDescrLen), MAXLEN_IFDESCR)
    raw = bytes(row.bDescr[:length])
    return raw.decode("mbcs", errors="replace").strip("\x00").strip()


def get_adapter_stats() -> list[AdapterStat]:
    if sys.platform != "win32":
        return []

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
    output = run_command(["tasklist", "/fo", "csv", "/nh"])
    processes: dict[str, str] = {}
    for row in csv.reader(output.splitlines()):
        if len(row) >= 2:
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


def get_netstat_snapshot() -> list[Connection]:
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
                    process=processes.get(pid, ""),
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
                    process=processes.get(pid, ""),
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


def build_analysis_rows(connections: list[Connection], adapter_rows: list[dict[str, object]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    external = [c for c in connections if not is_local_or_private_host(get_endpoint_host(c.remote))]
    established = [c for c in connections if c.state == "ESTABLISHED"]
    listening = [c for c in connections if c.state == "LISTENING"]
    udp_open = [c for c in connections if c.proto == "UDP"]
    waiting = [c for c in connections if c.state in {"TIME_WAIT", "CLOSE_WAIT"}]

    def add(level: str, finding: str, details: str) -> None:
        rows.append({"level": level, "finding": finding, "details": details})

    add(
        "Инфо",
        "Область сбора",
        (
            f"Наблюдено {len(connections)} уникальных сокетов: "
            f"{len(established)} установленных, {len(listening)} прослушивающих, "
            f"{len(udp_open)} UDP/открытых."
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
        add("Инфо", "Внешний трафик", f"{len(external)} сокетов указывают на публичные удаленные адреса.")
    else:
        add("Заметка", "В основном локальный трафик", "Публичные удаленные адреса не обнаружены.")

    top_processes = group_count(connections, "process", 5)
    if top_processes:
        add("Инфо", "Самые заметные процессы", ", ".join(f"{r['name']} ({r['count']})" for r in top_processes))

    external_processes = group_count(external, "process", 5)
    if external_processes:
        add(
            "Проверить",
            "Процессы с внешними подключениями",
            ", ".join(f"{r['name']} ({r['count']})" for r in external_processes),
        )

    external_ports = group_count(external, "remote_port", 5)
    if external_ports:
        add("Инфо", "Частые внешние порты", ", ".join(f"{r['name']} ({r['count']})" for r in external_ports))

    close_wait = [c for c in connections if c.state == "CLOSE_WAIT"]
    if close_wait:
        processes = ", ".join(f"{r['name']} ({r['count']})" for r in group_count(close_wait, "process", 5))
        add(
            "Проверить",
            "Сокеты CLOSE_WAIT",
            f"{len(close_wait)} сокетов ожидают закрытия локальным приложением. Процессы: {processes}.",
        )

    if len(waiting) > 30:
        add(
            "Заметка",
            "Много коротких соединений",
            f"{len(waiting)} сокетов находятся в TIME_WAIT/CLOSE_WAIT. Это часто бывает у браузеров и мессенджеров.",
        )

    non_web = [c for c in external if c.remote_port not in {"80", "443", "53", "123", "*", "0"}]
    if non_web:
        ports = ", ".join(f"{r['name']} ({r['count']})" for r in group_count(non_web, "remote_port", 5))
        add("Проверить", "Нестандартные внешние порты", f"{len(non_web)} сокетов используют порты: {ports}.")

    unknown = [c for c in connections if not c.process]
    if unknown:
        add(
            "Заметка",
            "Неизвестные процессы",
            f"{len(unknown)} сокетов не удалось связать с процессом. Возможно, процесс завершился во время сбора.",
        )

    return rows


def connection_rows(connections: list[Connection]) -> list[dict[str, object]]:
    return [
        {
            "observed_at": item.observed_at.strftime("%H:%M:%S"),
            "proto": item.proto,
            "local": item.local,
            "remote": item.remote,
            "state": item.state,
            "pid": item.pid,
            "process": item.process,
        }
        for item in sorted(connections, key=lambda row: row.observed_at)
    ]


def save_connections_csv(path: str, connections: Iterable[Connection]) -> None:
    fieldnames = ["observed_at", "proto", "local", "remote", "state", "pid", "process", "remote_port"]
    with open(path, "w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for item in sorted(connections, key=lambda row: row.observed_at):
            writer.writerow(
                {
                    "observed_at": item.observed_at.isoformat(timespec="seconds"),
                    "proto": item.proto,
                    "local": item.local,
                    "remote": item.remote,
                    "state": item.state,
                    "pid": item.pid,
                    "process": item.process,
                    "remote_port": item.remote_port,
                }
            )
