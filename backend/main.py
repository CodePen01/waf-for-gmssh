"""
@文件        :__init__.py
@说明        :This is an example
@时间        :2025/06/30 09:17:23
@作者        :xxx
@邮箱        :
@版本        :1.0.0
"""

from asyncio import run as asyncio_run

from app.server import app

if __name__ == "__main__":
    asyncio_run(app.run())
