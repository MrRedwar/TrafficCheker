# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import time
from datetime import datetime

from traffic_checker_core import (
    CaptureState,
    build_adapter_rows,
    build_analysis_rows,
    build_dns_cache,
    collect_host_reputation,
    collect_ip_owners,
    connection_rows,
    get_adapter_stats,
    get_netstat_snapshot,
    group_count,
    is_external_connection,
    merge_connection,
    owner_rows,
    reputation_rows,
    save_connections_csv,
    site_rows,
)


def print_table(title: str, rows: list[dict[str, object]], columns: list[str]) -> None:
    print()
    print(title)
    if not rows:
        print("  Нет данных.")
        return

    widths = {column: len(column) for column in columns}
    for row in rows:
        for column in columns:
            widths[column] = max(widths[column], len(str(row.get(column, ""))))

    print("  " + " | ".join(column.ljust(widths[column]) for column in columns))
    print("  " + "-+-".join("-" * widths[column] for column in columns))
    for row in rows:
        print("  " + " | ".join(str(row.get(column, "")).ljust(widths[column]) for column in columns))


def main() -> None:
    parser = argparse.ArgumentParser(description="Сбор и анализ сетевой активности устройства.")
    parser.add_argument("--duration", type=int, default=60, help="Длительность сбора в секундах.")
    parser.add_argument("--interval", type=int, default=5, help="Интервал выборки в секундах.")
    parser.add_argument("--csv", default="", help="Путь для сохранения CSV.")
    args = parser.parse_args()

    state = CaptureState(started_at=datetime.now(), adapter_start=get_adapter_stats())
    started = time.monotonic()
    print(f"Сбор начат на {args.duration} сек.")

    while True:
        for connection in get_netstat_snapshot():
            merge_connection(state.connections, connection)
        state.samples += 1

        elapsed = time.monotonic() - started
        if elapsed >= args.duration:
            break
        time.sleep(min(args.interval, max(1, args.duration - int(elapsed))))

    connections = list(state.connections.values())
    external_connections = [item for item in connections if is_external_connection(item)]
    adapter_rows = build_adapter_rows(state.adapter_start, get_adapter_stats())
    dns_cache = build_dns_cache()
    owner_cache = collect_ip_owners(connections, {}, limit=15)
    threat_cache = collect_host_reputation(connections, dns_cache, {}, limit=500)

    print(f"\nГотово. Выборок: {state.samples}. Сессий: {len(connections)}. Внешних: {len(external_connections)}.")
    print_table("Анализ", build_analysis_rows(connections, adapter_rows, dns_cache, owner_cache, threat_cache), ["level", "finding", "details"])
    print_table("Адаптеры", adapter_rows, ["adapter", "status", "received", "sent", "total"])
    print_table("Процессы", group_count(external_connections, "process", 25), ["name", "count"])
    print_table("Сайты", site_rows(connections, dns_cache=dns_cache, owner_cache=owner_cache, threat_cache=threat_cache, external_only=True, limit=25), ["site", "safety", "risk_rating", "owner", "process", "remote_port", "sessions", "first_seen", "last_seen", "ips"])
    print_table("Владельцы IP", owner_rows(external_connections, owner_cache=owner_cache, limit=25), ["owner", "sessions", "first_seen", "last_seen", "ips"])
    print_table("Безопасность", reputation_rows(external_connections, dns_cache=dns_cache, threat_cache=threat_cache, limit=25), ["site", "safety", "risk_rating", "threat_source", "threat_details", "sessions", "first_seen", "last_seen"])
    print_table("Состояния", group_count(external_connections, "state", 25), ["name", "count"])
    print_table("Порты", group_count(external_connections, "remote_port", 25), ["name", "count"])
    print_table(
        "Сессии",
        connection_rows(connections, external_only=True, dns_cache=dns_cache, owner_cache=owner_cache, threat_cache=threat_cache)[:25],
        ["first_seen", "last_seen", "seen_count", "site", "safety", "risk_rating", "owner", "proto", "local", "remote", "state", "pid", "process"],
    )

    if args.csv:
        save_connections_csv(args.csv, connections, dns_cache, owner_cache, threat_cache)
        print(f"\nCSV сохранен: {args.csv}")


if __name__ == "__main__":
    main()
