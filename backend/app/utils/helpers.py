import ssl
from asyncio import create_subprocess_shell as aio_subprocess_shell
from base64 import b64decode, b64encode
from json import dumps as json_dumps
from json import loads as json_loads
from random import Random
from re import IGNORECASE as re_I
from re import search as re_search
from subprocess import PIPE as subprocess_PIPE
from uuid import uuid4

import aiofiles
import aiohttp
from aiofiles import open as aio_open
from aiofiles.os import remove as aio_remove
from aiofiles.os import scandir
from aiofiles.ospath import exists as aio_exists
from aiofiles.ospath import isdir as aio_isdir
from aiofiles.ospath import isfile as aio_isfile

from app.utils.logger import logger

try:
    from simplejrpc.exceptions import RPCException
    from simplejrpc.i18n import T as i18n

    class GlobalException(RPCException):
        """全局RPC异常"""

        def __init__(self, err_msg_i18n="STATUS_ERROR", code=-1):
            err_msg = i18n.translate(err_msg_i18n)
            logger.error(err_msg)
            super().__init__(err_msg, code)

except Exception:

    class GlobalException(Exception):
        pass


async def read_file(file_path):
    """读取文件"""
    if not await aio_exists(file_path):
        logger.error(f"[文件读取] {file_path} 文件不存在")
        return ""
    logger.info(f"[文件读取] {file_path}")
    async with aio_open(file_path, "r", encoding="utf-8") as f:
        content = await f.read()
    return content


async def write_file(file_path, content):
    """写出文件"""
    logger.info(f"[文件写出] {file_path}")
    async with aio_open(file_path, "w", encoding="utf-8") as f:
        await f.write(content)


async def rm_file(file_path):
    """删除文件"""
    if not await aio_exists(file_path):
        logger.error(f"[文件删除] {file_path} 文件不存在")
        return
    logger.info(f"[文件删除] {file_path}")
    await aio_remove(file_path)


async def read_json(file_path):
    """读取json文件"""
    content = await read_file(file_path)
    data = json_loads(content)
    return data


async def write_json(file_path, data):
    """写出json文件"""
    content = json_dumps(data, ensure_ascii=False)
    await write_file(file_path, content)


async def read_json2(path, default=[]):
    if not await aio_exists(path):
        await write_json(path, default)
        return default
    return await read_json(path)


async def aio_walk(dir_path, pattern=None):
    """异步遍历目录，返回所有文件路径"""
    file_paths = []
    try:
        entries = await scandir(dir_path)
        for entry in entries:
            if await aio_isfile(entry.path):
                if pattern and not re_search(pattern, entry.path, re_I):
                    continue
                file_paths.append(entry.path)
            elif await aio_isdir(entry.path):
                sub_files = await aio_walk(entry.path, pattern)
                file_paths.extend(sub_files)
    except PermissionError:
        logger.error(f"无权限访问目录：{dir_path}")
    except FileNotFoundError:
        logger.error(f"目录不存在：{dir_path}")
    return file_paths


async def exec_shell(shell, cwd=None, sudo=True):
    """命令执行"""
    try:
        if sudo:
            shell = f"sudo {shell}" if not shell.startswith("sudo") else shell
        logger.info(f"[执行命令] {shell}")
        process = await aio_subprocess_shell(shell, stdout=subprocess_PIPE, stderr=subprocess_PIPE, cwd=cwd)
        stdout, stderr = await process.communicate()
        returncode = process.returncode
        stdout_str = stdout.decode("utf-8")
        stderr_str = stderr.decode("utf-8")
        out = f"{stdout_str}\n{stderr_str}".strip()
        if returncode != 0:
            return False, out
        return True, out

    except Exception:
        return False, ""


def SingletonDecorator(cls):
    """单例装饰器"""
    _instance = {}

    def _singleton(*args, **kwargs):
        if cls not in _instance:
            _instance[cls] = cls(*args, **kwargs)
        return _instance[cls]

    return _singleton


def paginate_data(data, page, page_size, desc=False, callback=None):
    """分页数据"""
    if not data:
        return {"list": [], "paginate": {"page_size": page_size, "total": 0}}
    if desc:
        data = data[::-1]
    total = len(data)
    data = data[(page - 1) * page_size : page * page_size]

    if callback:
        result = []
        for item in data:
            callback(item)
            result.append(item)
    else:
        result = data

    res = {
        "list": result,
        "paginate": {
            "total": total,
            "page_size": page_size,
        },
    }
    return res


def get_rand_str(length):
    """
    @name 取随机字符串
    @param length 要获取的长度
    @return string(length)
    """

    strings = ""
    chars = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789"
    chrlen = len(chars) - 1
    random = Random()
    for i in range(length):
        strings += chars[random.randint(0, chrlen)]
    return strings


def get_uuid():
    """获取uuid"""
    return str(uuid4())


def txt_to_base64(text, encoding="utf-8"):
    """将文本转换为 Base64 编码"""
    try:
        text_bytes = text.encode(encoding)
        base64_bytes = b64encode(text_bytes)
        base64_str = base64_bytes.decode(encoding)
        return base64_str
    except UnicodeEncodeError as e:
        logger.error(f"{text} 编码错误：{e}")
        return ""


def base64_to_text(base64_str, encoding="utf-8"):
    """将 Base64 编码转换为文本"""
    try:
        text = b64decode(base64_str).decode(encoding)
        return text
    except UnicodeDecodeError as e:
        logger.error(f"{base64_str} 解码错误：{e}")
        return ""


async def down_file(url, save_path):
    """异步下载ZIP文件"""
    chunk_size = 1024 * 1024  # 1MB分块
    # 创建SSL上下文，禁用证书验证
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    async with aiohttp.ClientSession() as session:
        try:
            # 传入ssl参数跳过证书验证
            async with session.get(url, ssl=ssl_context) as response:
                response.raise_for_status()  # 抛出HTTP错误
                async with aiofiles.open(save_path, "wb") as f:
                    async for chunk in response.content.iter_chunked(chunk_size):
                        await f.write(chunk)
        except Exception as e:
            logger.error(f"下载失败：{str(e)}")
            raise
