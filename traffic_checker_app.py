# -*- coding: utf-8 -*-
from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

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


class TrafficCheckerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("TrafficChecker")
        self.geometry("1120x720")
        self.minsize(920, 600)

        self.state = CaptureState()
        self.running = False
        self.capture_started_monotonic = 0.0
        self.stop_event = threading.Event()
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.show_internal_var = tk.BooleanVar(value=False)
        self.dns_cache: dict[str, set[str]] = {}
        self.owner_cache: dict[str, str] = {}
        self.threat_cache: dict[str, dict[str, str]] = {}
        self.last_dns_refresh = 0.0
        self.last_owner_refresh = 0.0
        self.last_threat_refresh = 0.0
        self.owner_lookup_running = False
        self.threat_lookup_running = False

        self._build_ui()
        self.after(200, self._process_events)

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=(12, 10))
        toolbar.pack(fill=tk.X)

        ttk.Label(toolbar, text="Режим: ручной сбор").pack(side=tk.LEFT, padx=(0, 18))

        self.start_button = ttk.Button(toolbar, text="Запустить", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT)

        self.stop_button = ttk.Button(toolbar, text="Остановить", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(10, 0))

        self.save_button = ttk.Button(toolbar, text="Сохранить CSV", command=self.save_csv, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=(10, 18))

        self.internal_check = ttk.Checkbutton(
            toolbar,
            text="Показывать внутренние",
            variable=self.show_internal_var,
            command=self._refresh_tables,
        )
        self.internal_check.pack(side=tk.LEFT, padx=(0, 18))

        self.status_var = tk.StringVar(value="Готово.")
        ttk.Label(toolbar, textvariable=self.status_var).pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill=tk.X, padx=8, pady=(0, 8))

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        self.grids: dict[str, ttk.Treeview] = {}
        self._add_grid("analysis", "Анализ", ["level", "finding", "details"])
        self._add_grid("adapters", "Адаптеры", ["adapter", "status", "received", "sent", "total"])
        self._add_grid("processes", "Процессы", ["name", "count"])
        self._add_grid("sites", "Сайты", ["site", "safety", "risk_rating", "owner", "process", "remote_port", "sessions", "first_seen", "last_seen", "ips"])
        self._add_grid("owners", "Владельцы IP", ["owner", "sessions", "first_seen", "last_seen", "ips"])
        self._add_grid("security", "Безопасность", ["site", "safety", "risk_rating", "threat_source", "threat_details", "sessions", "first_seen", "last_seen"])
        self._add_grid("states", "Состояния", ["name", "count"])
        self._add_grid("ports", "Порты", ["name", "count"])
        self._add_grid(
            "connections",
            "Сессии",
            ["first_seen", "last_seen", "seen_count", "site", "safety", "risk_rating", "owner", "proto", "local", "remote", "state", "pid", "process"],
        )

    def _add_grid(self, key: str, title: str, columns: list[str]) -> None:
        frame = ttk.Frame(self.tabs)
        self.tabs.add(frame, text=title)

        tree = ttk.Treeview(frame, columns=columns, show="headings")
        y_scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        x_scroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        headers = {
            "level": "Уровень",
            "finding": "Вывод",
            "details": "Подробности",
            "adapter": "Адаптер",
            "status": "Статус",
            "received": "Получено",
            "sent": "Отправлено",
            "total": "Всего",
            "name": "Название",
            "count": "Количество",
            "first_seen": "Первый раз",
            "last_seen": "Последний раз",
            "seen_count": "Повторы",
            "site": "Сайт/домен",
            "owner": "Владелец IP",
            "safety": "Репутация",
            "risk_rating": "Рейтинг",
            "threat_source": "Источник",
            "threat_details": "Детали проверки",
            "sessions": "Сессии",
            "ips": "IP-адреса",
            "proto": "Протокол",
            "local": "Локальный адрес",
            "remote": "Удаленный адрес",
            "state": "Состояние",
            "pid": "PID",
            "process": "Процесс",
        }
        widths = {
            "details": 560,
            "finding": 240,
            "adapter": 320,
            "local": 220,
            "remote": 220,
            "process": 180,
            "site": 300,
            "owner": 260,
            "safety": 170,
            "risk_rating": 140,
            "threat_details": 420,
            "ips": 260,
        }

        for column in columns:
            tree.heading(column, text=headers.get(column, column))
            tree.column(column, width=widths.get(column, 120), stretch=True)

        self.grids[key] = tree

    def set_rows(self, key: str, rows: list[dict[str, object]]) -> None:
        tree = self.grids[key]
        tree.delete(*tree.get_children())
        columns = tree["columns"]
        for row in rows:
            tree.insert("", tk.END, values=[row.get(column, "") for column in columns])

    def start_capture(self) -> None:
        if self.running:
            return

        self.state = CaptureState(started_at=datetime.now(), adapter_start=get_adapter_stats())
        self.running = True
        self.capture_started_monotonic = time.monotonic()
        self.dns_cache = build_dns_cache()
        self.owner_cache = {}
        self.threat_cache = {}
        self.last_dns_refresh = time.monotonic()
        self.last_owner_refresh = 0.0
        self.last_threat_refresh = 0.0
        self.owner_lookup_running = False
        self.threat_lookup_running = False
        self.stop_event.clear()
        self.start_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.save_button.configure(state=tk.DISABLED)
        self.progress.start(12)
        self.status_var.set("Идет анализ...")

        for key in self.grids:
            self.set_rows(key, [])

        worker = threading.Thread(target=self._capture_worker, daemon=True)
        worker.start()

    def stop_capture(self) -> None:
        if not self.running:
            return
        self.stop_button.configure(state=tk.DISABLED)
        self.status_var.set("Останавливаю сбор...")
        self.stop_event.set()

    def _capture_worker(self) -> None:
        started = time.monotonic()

        while not self.stop_event.is_set():
            try:
                snapshot = get_netstat_snapshot()
                self.events.put(("snapshot", snapshot))
            except Exception as exc:
                self.events.put(("error", str(exc)))
                return

            elapsed = time.monotonic() - started
            self.events.put(("progress", elapsed))

            if self.stop_event.wait(1):
                break

        self.events.put(("done", time.monotonic() - started))

    def _process_events(self) -> None:
        while True:
            try:
                event, payload = self.events.get_nowait()
            except queue.Empty:
                break

            if event == "snapshot":
                self._merge_snapshot(payload)
                self._refresh_tables()
            elif event == "progress":
                self._update_progress(float(payload))
            elif event == "dns":
                self.dns_cache = payload
                self.last_dns_refresh = time.monotonic()
                self._refresh_tables()
            elif event == "owners":
                self.owner_cache.update(payload)
                self.owner_lookup_running = False
                self.last_owner_refresh = time.monotonic()
                self._refresh_tables()
            elif event == "threats":
                self.threat_cache.update(payload)
                self.threat_lookup_running = False
                self.last_threat_refresh = time.monotonic()
                self._refresh_tables()
            elif event == "error":
                self.running = False
                self.status_var.set(f"Ошибка сбора: {payload}")
                self.start_button.configure(state=tk.NORMAL)
                self.stop_button.configure(state=tk.DISABLED)
                self.progress.stop()
            elif event == "done":
                self._finish_capture(float(payload or 0))

        self.after(200, self._process_events)

    def _merge_snapshot(self, snapshot: object) -> None:
        for connection in snapshot:
            merge_connection(self.state.connections, connection)
        self.state.samples += 1

    def _update_progress(self, elapsed: float) -> None:
        if self.running and time.monotonic() - self.last_dns_refresh >= 10:
            threading.Thread(target=self._refresh_dns_cache, daemon=True).start()
        if self.running and not self.owner_lookup_running and time.monotonic() - self.last_owner_refresh >= 15:
            self.owner_lookup_running = True
            threading.Thread(target=self._refresh_owner_cache, daemon=True).start()
        if self.running and not self.threat_lookup_running and time.monotonic() - self.last_threat_refresh >= 20:
            self.threat_lookup_running = True
            threading.Thread(target=self._refresh_threat_cache, daemon=True).start()
        if self.running:
            self.status_var.set(f"Идет анализ... прошло {self._format_elapsed(elapsed)}.")

    def _refresh_dns_cache(self) -> None:
        self.last_dns_refresh = time.monotonic()
        self.events.put(("dns", build_dns_cache()))

    def _refresh_owner_cache(self) -> None:
        connections = list(self.state.connections.values())
        updates = collect_ip_owners(connections, self.owner_cache.copy(), limit=8)
        self.events.put(("owners", updates))

    def _refresh_threat_cache(self) -> None:
        connections = list(self.state.connections.values())
        updates = collect_host_reputation(connections, self.dns_cache, self.threat_cache.copy(), limit=500)
        self.events.put(("threats", updates))

    @staticmethod
    def _format_elapsed(elapsed: float) -> str:
        total = max(0, int(elapsed))
        minutes, seconds = divmod(total, 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        return f"{minutes:02d}:{seconds:02d}"

    def _refresh_tables(self) -> None:
        connections = list(self.state.connections.values())
        visible_connections = connections if self.show_internal_var.get() else [item for item in connections if is_external_connection(item)]
        adapter_rows = build_adapter_rows(self.state.adapter_start, get_adapter_stats())

        self.set_rows("analysis", build_analysis_rows(connections, adapter_rows, self.dns_cache, self.owner_cache, self.threat_cache))
        self.set_rows("adapters", [{key: row[key] for key in ("adapter", "status", "received", "sent", "total")} for row in adapter_rows])
        self.set_rows("processes", group_count(visible_connections, "process", 100))
        self.set_rows("sites", site_rows(connections, dns_cache=self.dns_cache, owner_cache=self.owner_cache, threat_cache=self.threat_cache, external_only=not self.show_internal_var.get()))
        self.set_rows("owners", owner_rows(visible_connections, owner_cache=self.owner_cache))
        self.set_rows("security", reputation_rows(visible_connections, dns_cache=self.dns_cache, threat_cache=self.threat_cache))
        self.set_rows("states", group_count(visible_connections, "state", 100))
        self.set_rows("ports", group_count(visible_connections, "remote_port", 100))
        self.set_rows("connections", connection_rows(connections, external_only=not self.show_internal_var.get(), dns_cache=self.dns_cache, owner_cache=self.owner_cache, threat_cache=self.threat_cache))

    def _finish_capture(self, elapsed: float) -> None:
        self.running = False
        self.progress.stop()
        self._refresh_tables()
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
        self.save_button.configure(state=tk.NORMAL)
        self.status_var.set(f"Готово. Время сбора: {self._format_elapsed(elapsed)}. Найдено сессий: {len(self.state.connections)}.")

    def save_csv(self) -> None:
        if not self.state.connections:
            messagebox.showinfo("TrafficChecker", "Нет данных для сохранения.")
            return

        path = filedialog.asksaveasfilename(
            title="Сохранить CSV",
            defaultextension=".csv",
            filetypes=[("CSV-файлы", "*.csv"), ("Все файлы", "*.*")],
            initialfile="traffic-report.csv",
        )
        if not path:
            return

        save_connections_csv(path, self.state.connections.values(), self.dns_cache, self.owner_cache, self.threat_cache)
        messagebox.showinfo("TrafficChecker", f"CSV сохранен: {path}")


if __name__ == "__main__":
    app = TrafficCheckerApp()
    app.mainloop()
