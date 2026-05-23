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
    connection_rows,
    get_adapter_stats,
    get_netstat_snapshot,
    group_count,
    save_connections_csv,
)


DURATIONS = {
    "15 секунд": 15,
    "30 секунд": 30,
    "1 минута": 60,
    "3 минуты": 180,
    "5 минут": 300,
}


class TrafficCheckerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("TrafficChecker")
        self.geometry("1120x720")
        self.minsize(920, 600)

        self.state = CaptureState()
        self.running = False
        self.duration = 60
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()

        self._build_ui()
        self.after(200, self._process_events)

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=(12, 10))
        toolbar.pack(fill=tk.X)

        ttk.Label(toolbar, text="Время анализа:").pack(side=tk.LEFT)
        self.duration_var = tk.StringVar(value="1 минута")
        self.duration_box = ttk.Combobox(
            toolbar,
            textvariable=self.duration_var,
            values=list(DURATIONS.keys()),
            state="readonly",
            width=14,
        )
        self.duration_box.pack(side=tk.LEFT, padx=(8, 18))

        self.start_button = ttk.Button(toolbar, text="Запустить", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT)

        self.save_button = ttk.Button(toolbar, text="Сохранить CSV", command=self.save_csv, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=(10, 18))

        self.status_var = tk.StringVar(value="Готово.")
        ttk.Label(toolbar, textvariable=self.status_var).pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(self, maximum=100)
        self.progress.pack(fill=tk.X, padx=8, pady=(0, 8))

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        self.grids: dict[str, ttk.Treeview] = {}
        self._add_grid("analysis", "Анализ", ["level", "finding", "details"])
        self._add_grid("adapters", "Адаптеры", ["adapter", "status", "received", "sent", "total"])
        self._add_grid("processes", "Процессы", ["name", "count"])
        self._add_grid("states", "Состояния", ["name", "count"])
        self._add_grid("ports", "Порты", ["name", "count"])
        self._add_grid("connections", "Соединения", ["observed_at", "proto", "local", "remote", "state", "pid", "process"])

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
            "observed_at": "Замечено",
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

        self.duration = DURATIONS[self.duration_var.get()]
        self.state = CaptureState(started_at=datetime.now(), adapter_start=get_adapter_stats())
        self.running = True
        self.start_button.configure(state=tk.DISABLED)
        self.duration_box.configure(state=tk.DISABLED)
        self.save_button.configure(state=tk.DISABLED)
        self.progress["value"] = 0
        self.status_var.set("Идет анализ...")

        for key in self.grids:
            self.set_rows(key, [])

        worker = threading.Thread(target=self._capture_worker, daemon=True)
        worker.start()

    def _capture_worker(self) -> None:
        started = time.monotonic()

        while True:
            try:
                snapshot = get_netstat_snapshot()
                self.events.put(("snapshot", snapshot))
            except Exception as exc:
                self.events.put(("error", str(exc)))
                return

            elapsed = time.monotonic() - started
            self.events.put(("progress", elapsed))
            if elapsed >= self.duration:
                self.events.put(("done", None))
                return
            time.sleep(1)

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
            elif event == "error":
                self.running = False
                self.status_var.set(f"Ошибка сбора: {payload}")
                self.start_button.configure(state=tk.NORMAL)
                self.duration_box.configure(state="readonly")
            elif event == "done":
                self._finish_capture()

        self.after(200, self._process_events)

    def _merge_snapshot(self, snapshot: object) -> None:
        for connection in snapshot:
            self.state.connections.setdefault(connection.key, connection)
        self.state.samples += 1

    def _update_progress(self, elapsed: float) -> None:
        percent = min(100, int((elapsed / self.duration) * 100))
        left = max(0, self.duration - int(elapsed))
        self.progress["value"] = percent
        if self.running:
            self.status_var.set(f"Идет анализ... осталось {left} сек.")

    def _refresh_tables(self) -> None:
        connections = list(self.state.connections.values())
        adapter_rows = build_adapter_rows(self.state.adapter_start, get_adapter_stats())

        self.set_rows("analysis", build_analysis_rows(connections, adapter_rows))
        self.set_rows("adapters", [{key: row[key] for key in ("adapter", "status", "received", "sent", "total")} for row in adapter_rows])
        self.set_rows("processes", group_count(connections, "process", 100))
        self.set_rows("states", group_count(connections, "state", 100))
        self.set_rows("ports", group_count(connections, "remote_port", 100))
        self.set_rows("connections", connection_rows(connections))

    def _finish_capture(self) -> None:
        self.running = False
        self.progress["value"] = 100
        self._refresh_tables()
        self.start_button.configure(state=tk.NORMAL)
        self.duration_box.configure(state="readonly")
        self.save_button.configure(state=tk.NORMAL)
        self.status_var.set(f"Готово. Найдено соединений: {len(self.state.connections)}.")

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

        save_connections_csv(path, self.state.connections.values())
        messagebox.showinfo("TrafficChecker", f"CSV сохранен: {path}")


if __name__ == "__main__":
    app = TrafficCheckerApp()
    app.mainloop()
