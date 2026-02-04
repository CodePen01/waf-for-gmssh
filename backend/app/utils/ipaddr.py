from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

from app.consts.enums import IPTypeEnum


def get_ip_type(ip):
    """获取ip类型"""
    ip = ip.strip()
    try:
        if "-" in ip:
            ip_parts = ip.split("-")
            if len(ip_parts) != 2:
                return False, "Invalid IP range"
            ip, _ = str(ip_address(ip_parts[0])), str(ip_address(ip_parts[1]))
        else:
            net = ip_network(ip, strict=False)
            ip = str(net.network_address)
        ip_obj = ip_address(ip)
        if isinstance(ip_obj, IPv4Address):
            return True, IPTypeEnum.ipv4
        elif isinstance(ip_obj, IPv6Address):
            return True, IPTypeEnum.ipv6
    except Exception:
        return False, "Invalid IP"


def is_ipv4(ip):
    """判断是否为ipv4"""
    try:
        ip_obj = ip_address(ip)
        if isinstance(ip_obj, IPv4Address):
            return True
    except Exception:
        pass
    return False


def ip2long(ip):
    """ip转long"""
    return int(ip_address(ip))


def long2ip(long):
    """long转ip"""
    return str(ip_address(long))


def get_ip_range(ip, long=False):
    """获取ip范围"""
    try:
        ip = ip.strip()
        if not any(["-" in ip, "/" in ip]):
            _ip = str(ip_address(ip))
            start, end = _ip, _ip
        elif "-" in ip:
            start, end = ip.split("-")
            start, end = str(ip_address(start)), str(ip_address(end))
        else:
            net = ip_network(ip, strict=False)
            start = str(net.network_address)
            end = str(net[-1])
        return True, (ip2long(start), ip2long(end)) if long else (start, end)
    except Exception:
        return False, "Invalid IP range"
