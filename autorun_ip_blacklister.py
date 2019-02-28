import asyncio
from ip_blacklister import main
from apscheduler.schedulers.blocking import BlockingScheduler
import datetime


def run():
    print(f"ip blacklister starting to scan access.log @ {datetime.datetime.now()}")
    loop = asyncio.get_event_loop()
    loop.run_until_complete(test())
    print(f"ip blacklister scanned access.log @ {datetime.datetime.now()}\n\n")


if __name__ == '__main__':
    scheduler = BlockingScheduler()
    scheduler.add_executor("processpool")
    scheduler.add_job(main, "cron",
                      hour=12,
                      misfire_grace_time=3600,
                      name=f"scan @ {datetime.datetime.now()}")
    print("Started ip blacklister")
    print("ip blacklister will scan access.log at 12:00 local time")
    scheduler.start()
