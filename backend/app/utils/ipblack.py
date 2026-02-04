from re import findall as re_findall

from app.consts.settings import PATH_WAF_IPSET_FILE
from app.utils.helpers import exec_shell, write_file


async def ipblack_add(ip):
    """拦截黑名单添加ip"""
    data = f"+,{ip}"
    await write_file(PATH_WAF_IPSET_FILE, data)


async def ipblack_del(ip):
    """拦截黑名单删除ip"""
    data = f"-,{ip}"
    await write_file(PATH_WAF_IPSET_FILE, data)


async def ipblack_clear():
    """拦截黑名单清空"""
    data = "-,0.0.0.0"
    await write_file(PATH_WAF_IPSET_FILE, data)


async def get_ipblack_list():
    """拦截黑名单清空"""
    matches = []
    pattern = r"(.*)\s+timeout\s+(\d+)"

    shell = "ipset list waf_ip_filter"
    flag, res = await exec_shell(shell)
    if flag:
        matches = matches + re_findall(pattern, res)

    shell = "ipset list waf_ip_filter_v6"
    flag, res = await exec_shell(shell)
    if flag:
        matches = matches + re_findall(pattern, res)

    data = [{"ip": ip.strip(), "timeout": int(timeout)} for ip, timeout in matches if ip.strip() and "Header" not in ip]
    return data
