# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import time
from datetime import datetime

from traffic_checker_core import (
    CaptureState,
    build_adapter_rows,
    build_analysis_rows,
    connection_rows,
    get_adapter_stats,
    get_netstat_snapshot,
    group_count,
    save_connections_csv,
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
            state.connections.setdefault(connection.key, connection)
        state.samples += 1

        elapsed = time.monotonic() - started
        if elapsed >= args.duration:
            break
        time.sleep(min(args.interval, max(1, args.duration - int(elapsed))))

    connections = list(state.connections.values())
    adapter_rows = build_adapter_rows(state.adapter_start, get_adapter_stats())

    print(f"\nГотово. Выборок: {state.samples}. Соединений: {len(connections)}.")
    print_table("Анализ", build_analysis_rows(connections, adapter_rows), ["level", "finding", "details"])
    print_table("Адаптеры", adapter_rows, ["adapter", "status", "received", "sent", "total"])
    print_table("Процессы", group_count(connections, "process", 25), ["name", "count"])
    print_table("Состояния", group_count(connections, "state", 25), ["name", "count"])
    print_table("Порты", group_count(connections, "remote_port", 25), ["name", "count"])
    print_table("Соединения", connection_rows(connections)[:25], ["observed_at", "proto", "local", "remote", "state", "pid", "process"])

    if args.csv:
        save_connections_csv(args.csv, connections)
        print(f"\nCSV сохранен: {args.csv}")


if __name__ == "__main__":
    main()
