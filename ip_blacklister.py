import asyncio
import os
import re
import json
import datetime
import aiohttp
import aiosqlite
from yarl import URL

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def log(message: str, file="ip_blacklister.log") -> None:
    file = os.path.join(PROJECT_ROOT, file)
    with open(file, "a") as f:
        f.write(message + "\n")


def get_api() -> str:
    """
    returns the api key from the settings.json file

    :return: str, abuseipdb api key
    """
    file = os.path.join(PROJECT_ROOT, "settings.json")
    with open(file, "r") as f:
        data = json.load(f)
        return data["api"]


def get_access_log() -> str:
    """
    returns the access log filepath from the settings.json file

    :return: str, apache2 log filepath
    """
    file = os.path.join(PROJECT_ROOT, "settings.json")
    with open(file, "r") as f:
        data = json.load(f)
        return data["access_log"]


def read_access_log(location: str) -> set:
    """
    reads the access log and searches for ip adresses

    :param location: str, apache2 log filepath
    :return: set, ip adresses
    """
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    with open(location) as file:
        ips = set()
        for line in file:
            match = ip_pattern.findall(line)
            if match:
                ips.update(match)
        return ips


async def get_all_old_ips(db="db.db") -> set:
    """
    returns all ip addresses in database that have not been evaluated in 30 days

    :param db: str, sqlite db file
    :return: set, ip addresses older than 30 days
    """
    db = os.path.join(PROJECT_ROOT, db)
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
    db = os.path.join(PROJECT_ROOT, db)
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

        return [(await task)["data"] for task in tasks]


async def store_ips(*ips: str, db="db.db") -> None:
    """
    stores the ips in the database with current date

    :param ips: str, ip adresses
    :param db: str, sqlite database name
    :return: None
    """
    db = os.path.join(PROJECT_ROOT, db)
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
    db = os.path.join(PROJECT_ROOT, db)
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


async def main() -> None:
    api = get_api()
    access_log = get_access_log()

    log_ips = read_access_log(access_log)
    recent_ips = await get_all_recent_ips()
    old_ips = await get_all_old_ips()

    data = await check_ips(*log_ips.difference(recent_ips).union(old_ips), api=api)
    evaluate_ip_ban(data)

    await store_ips(*log_ips.difference(old_ips).difference(recent_ips))
    await update_ips(*old_ips)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
