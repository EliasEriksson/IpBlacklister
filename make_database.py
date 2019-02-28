import aiosqlite
import asyncio
import os


async def make_database(db: str):
    if not os.path.isfile(db):
        ip_table = """
        CREATE TABLE `iptable` (
            `id`	INTEGER PRIMARY KEY AUTOINCREMENT,
            `ip`	TEXT UNIQUE,
            `day`   TEXT
        );"""
        async with aiosqlite.connect(db) as connection:
            cursor = await connection.cursor()
            await cursor.execute(ip_table)
            await connection.commit()
        print(f"created new database {db}")
    else:
        print(f"database {db} already excists.")


async def main():
    await make_database("db.db")

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
