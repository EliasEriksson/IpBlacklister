from ip_blacklister import main
import os
import asyncio
import datetime
from apscheduler.schedulers.blocking import BlockingScheduler


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def log(message: str, file="ip_blacklister.log") -> None:
    file = os.path.join(PROJECT_ROOT, file)
    with open(file, "a") as f:
        f.write(message + "\n")


def run():
    log(f"ip blacklister starting to scan access.log @ {datetime.datetime.now()}")
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    log(f"ip blacklister scanned access.log @ {datetime.datetime.now()}\n\n")


if __name__ == '__main__':
    scheduler = BlockingScheduler()
    scheduler.add_executor("processpool")
    scheduler.add_job(run, "cron",
                      hour=12,
                      misfire_grace_time=3600,
                      name=f"scan @ {datetime.datetime.now()}")
    log(f"\nStarted ip blacklister @ {datetime.datetime.now()}")
    log("ip blacklister will scan access.log at 12:00 local time")
    scheduler.start()
