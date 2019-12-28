from .ip_blacklister import main, log, get_settings
from . import NoSuchMode
from typing import Dict, Any
from time import sleep
import datetime
import asyncio
from pathlib import Path, PosixPath
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from watchdog.events import FileModifiedEvent, FileSystemEvent
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class Watchdog(FileSystemEventHandler):
    def __init__(self, settings: Dict[str, Any]) -> None:
        super(Watchdog, self).__init__()

        self.settings = settings
        self.events = [FileModifiedEvent(log_) for log_ in settings["logs"]]
        self.loop = asyncio.get_event_loop()

    def on_modified(self, event: FileSystemEvent) -> None:
        if event in self.events:
            self.loop.run_until_complete(main(self.settings))


def _run_with_watchdog(settings: Dict[str, Any]) -> None:
    event_handler = Watchdog(settings)
    observer = Observer()
    for log_ in settings["logs"]:
        directory: PosixPath = Path(log_).parent
        if directory.exists():
            observer.schedule(event_handler, str(directory), True)
        else:
            settings["logs"].remove(log_)

    observer.start()
    try:
        while True:
            sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def _run_with_schedule(settings: Dict[str, Any]) -> None:
    scheduler = AsyncIOScheduler()
    scheduler.add_executor("processpool")
    scheduler.add_job(main, "cron",
                      args=[settings],
                      hour=12,
                      misfire_grace_time=3600,
                      name=f"scan @ {datetime.datetime.now()}")
    log(f"\nStarted ip blacklister @ {datetime.datetime.now()}")
    log("ip blacklister will scan access.log at 12:00 local time")
    scheduler.start()
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass


def run() -> None:
    settings: Dict[str, Any] = get_settings()
    if settings["mode"] == "watchdog":
        _run_with_watchdog(settings)
    elif settings["mode"] == "schedule":
        _run_with_schedule(settings)

    elif settings["mode"] == "single_run":
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main(settings))
    else:
        raise NoSuchMode(settings["modes"])


if __name__ == '__main__':
    run()
