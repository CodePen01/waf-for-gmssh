"""统一时间处理"""

from datetime import datetime, timedelta

# 规范时间戳格式
TIME_FORMAT = r"%Y-%m-%d %H:%M:%S"


def now():
    return datetime.now()


def now2str(_format=TIME_FORMAT):
    """转字符串"""
    return datetime.now().strftime(_format)


def now2int(unit="s"):
    """时间戳"""
    ret = datetime.now().timestamp()
    if unit == "ms":
        return int(1000 * ret)
    return int(ret)


def dtime2str(dt_obj, _format=TIME_FORMAT):
    """转字符串"""
    if isinstance(dt_obj, str):
        return dt_obj
    elif isinstance(dt_obj, int):
        return datetime.fromtimestamp(dt_obj).strftime(_format)
    elif isinstance(dt_obj, datetime):
        return dt_obj.strftime(_format)
    else:
        raise Exception("不支持的类型")


def dtime2obj(dt_obj, _format=TIME_FORMAT):
    """转变datetime对象"""
    if isinstance(dt_obj, str):
        return datetime.strptime(dt_obj, _format)
    elif isinstance(dt_obj, int):
        return datetime.fromtimestamp(dt_obj)
    elif isinstance(dt_obj, datetime):
        return dt_obj
    else:
        raise Exception("不支持的类型")


def dtime2int(dt_obj, _format=TIME_FORMAT):
    """转时间戳"""
    if isinstance(dt_obj, str):
        return int(datetime.strptime(dt_obj, _format).timestamp())
    elif isinstance(dt_obj, int):
        return dt_obj
    elif isinstance(dt_obj, datetime):
        return int(dt_obj.timestamp())
    else:
        raise Exception("不支持的类型")


def diff_dtime(dt_obj1, dt_obj2, _abs=False):
    """传入时间 减 当前时间 的秒数
    _abs 绝对值
    """
    ret = int(dtime2int(dt_obj1) - dtime2int(dt_obj2))
    if not _abs:
        return ret
    return abs(ret)


def diff_dtime_now(dt_obj, _abs=False):
    """传入时间 减 当前时间 的秒数
    _abs 绝对值
    """
    ret = int(dtime2int(dt_obj) - now2int())
    if not _abs:
        return ret
    return abs(ret)
