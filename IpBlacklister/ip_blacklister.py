from . import PROJECT_ROOT
from typing import Dict, Any
import datetime
import asyncio
import json
import os
import re
import aiohttp
import aiosqlite
from yarl import URL


def log(message: str, file="ip_blacklister.log") -> None:
    with PROJECT_ROOT.joinpath(file).open("a") as f:
        f.write("\n" + message)


def get_settings(*fields: str) -> Dict[str, Any]:
    with PROJECT_ROOT.joinpath("settings.json").open() as f:
        data: dict = json.load(f)
    if fields:
        return {field: data[field] for field in fields}
    else:
        return data


def read_log(*locations: str) -> set:
    """
    reads the access log and searches for ip adresses

    :param locations: str, apache2 log filepath
    :return: set, ip adresses
    """

    # TODO rework to only read the last few lines of a file
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    ips = set()
    for location in locations:
        try:
            with open(location) as file:
                for line in file:
                    match = ip_pattern.findall(line)
                    if match:
                        ips.update(match)
        except FileNotFoundError:
            log(f"File `{location}` does not exist.")

    return ips


async def get_all_old_ips(db="db.db") -> set:
    """
    returns all ip addresses in database that have not been evaluated in 30 days

    :param db: str, sqlite db file
    :return: set, ip addresses older than 30 days
    """
    db = str(PROJECT_ROOT.joinpath(db))
    async with aiosqlite.connect(db) as connection:
        cursor = await connection.cursor()
        sql = "select ip from iptable " \
              "where not day between date('now', '-30 day') and date('now')"
        await cursor.execute(sql)
        return set(ip[0] for ip in await cursor.fetchall())


async def get_all_recent_ips(db="db.db") -> set:
    """
    returns all ip addresses the database that are evaluated the last 30 days

    :param db: str, sqlite db file
    :return: set, ip adresses newer than 30 days
    """
    db = str(PROJECT_ROOT.joinpath(db))
    async with aiosqlite.connect(db) as connection:
        cursor = await connection.cursor()
        sql = "select ip from iptable " \
              "where day between date('now', '-30 day') and date('now')"
        await cursor.execute(sql)
        return set(ip[0] for ip in await cursor.fetchall())


async def request_url(url: str, session: aiohttp.ClientSession) -> dict:
    """
    requests a abuseipdb api url and returns its data

    :param url: str, abuseipdb api url
    :param session: aiohttp.ClientSession, client session with api key in header
    :return: dict, data about an api
    """
    async with session.get(url) as response:
        if response.status == 200:
            return await response.json(encoding="utf-8")
        else:
            return {}


async def check_ips(*ips: str, max_age="30", api: str) -> list:
    """
    requests abuseipdb with given ips on /check endpoint

    :param ips: str, ip addresses
    :param max_age: str, repports not older than 30 days
    :param api: str, abuseipdb api key
    :return: list, listof dicts with data about each ip
    """
    headers = {
        "Key": api,
        "Accept": "applications/json"}
    base_url = "https://api.abuseipdb.com/api/v2/check"
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = []
        for ip in ips:
            tasks.append(asyncio.create_task(request_url(
                f"{base_url}?ipAddress={URL(ip)}&maxAgeInDays={URL(max_age)}",
                session)))

        return [result["data"] for result in [(await task) for task in tasks] if result]


async def store_ips(*ips: str, db="db.db") -> None:
    """
    stores the ips in the database with current date

    :param ips: str, ip adresses
    :param db: str, sqlite database name
    :return: None
    """
    db = str(PROJECT_ROOT.joinpath(db))
    async with aiosqlite.connect(db) as connecton:
        cursor = await connecton.cursor()
        for ip in ips:
            day = datetime.date.today()
            sql = "insert or ignore into iptable (" \
                  "    'ip', 'day'" \
                  ") values (" \
                  f"    '{ip}', '{day.strftime('%Y-%m-%d')}'" \
                  ")"
            await cursor.execute(sql)
        await connecton.commit()


async def update_ips(*ips: str, db="db.db") -> None:
    """
    updates the date of given ips in the database

    :param ips: str, ip addresses
    :param db: str, sqlite database filepath
    :return: None
    """
    db = str(PROJECT_ROOT.joinpath(db))
    async with aiosqlite.connect(db) as connection:
        cursor = await connection.cursor()
        today = datetime.date.today()
        for ip in ips:
            sql = f"update iptable" \
                  f"    set (day)" \
                  f"       =('{today.strftime('%Y-%m-%d')}')" \
                  f"where ip='{ip}'"
            await cursor.execute(sql)
        await connection.commit()


def evaluate_ip_ban(data: list) -> None:
    """
    evaluates if an ip address is acting abusive calls ban on it if it is

    :param data: dict, abuseipdb data about ip address
    :return: None
    """
    for request in data:
        if request["abuseConfidenceScore"] > 70:
            if request["totalReports"] > 10:
                ban(request["ipAddress"])


def ban(ip: str) -> None:
    """
    calls system command for ban on given ip

    :param ip: str, ip address
    :return: None
    """
    os.system(f"ufw deny from {ip} to any")
    log(f"Banned {ip} date: {datetime.date.today()}")


async def main(settings: Dict[str, Any]) -> None:
    log(f"\nip blacklister starting to scan loggs @ {datetime.datetime.now()}")

    log_ips = read_log(*settings["logs"])

    recent_ips = await get_all_recent_ips()
    old_ips = await get_all_old_ips()

    data = await check_ips(*log_ips.difference(recent_ips).union(old_ips), api=settings["api"])
    evaluate_ip_ban(data)

    await store_ips(*log_ips.difference(old_ips).difference(recent_ips))
    await update_ips(*old_ips)
    log(f"ip blacklister scanned loggs @ {datetime.datetime.now()}")


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main(get_settings()))
