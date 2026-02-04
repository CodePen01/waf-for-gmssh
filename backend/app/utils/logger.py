from traceback import format_exc

from loguru import logger

from app.utils.helpers import GlobalException

logger.add("log/waf_{time:YYYYMMDD}.log", rotation="1 day", retention="7 days")


def print_exc(func=None):
    """打印异常栈"""
    if func is None:
        logger.error(format_exc())
        return

    # 异步包装函数
    async def wrapper(*args, **kwargs):
        """包装函数的文档字符串"""
        try:
            return await func(*args, **kwargs)
        except Exception:
            logger.error(format_exc())
            raise GlobalException("API_CALL_ERROR")

    return wrapper


logger.print_exc = print_exc
