from pathlib import Path
from re import IGNORECASE as re_I
from re import search as re_search

from aiofiles.ospath import exists as aio_exists

from app.consts.settings import (
    PATH_APP_ZDGL,
    PATH_NGINX_SERVICE,
    PATH_WAF_LUA_CONFIG,
    PATH_WAF_LUA_DOMAINS,
    PATH_WAF_LUA_SITE,
)
from app.utils.dt_time import now2str
from app.utils.helpers import (
    aio_walk,
    exec_shell,
    read_file,
    read_json,
    rm_file,
    write_json,
)
from app.utils.logger import logger


async def nginx_restart():
    """重载nginx配置"""
    if not await aio_exists(PATH_NGINX_SERVICE):
        flag, out = await exec_shell("systemctl restart nginx")
        if not flag:
            logger.error(f"nginx restart failed: {out}")
            await exec_shell("pkill -9 nginx")
            flag, _ = await exec_shell("systemctl restart nginx")
            if not flag:
                logger.error("nginx重启失败, 正在还原nginx关闭waf")
                await exec_shell('sed -i "/load_module/d" /etc/nginx/nginx.conf')
                await exec_shell(r'sed -i "/include \/www\/server\/safewaf\/env\/open_conf\/safewaf.conf;/d" /etc/nginx/nginx.conf')
                await exec_shell("systemctl restart nginx")

        return
    flag, out = await exec_shell(f"{PATH_NGINX_SERVICE} restart")
    if flag:
        logger.info("nginx restart success")
    else:
        logger.error(f"nginx restart failed: {out}")


async def read_waf_config():
    """读取waf配置"""
    return await read_json(PATH_WAF_LUA_CONFIG)


async def write_waf_config(config):
    """写入waf配置"""
    await write_json(PATH_WAF_LUA_CONFIG, config)


async def read_waf_site():
    """读取waf站点配置"""
    if not await aio_exists(PATH_WAF_LUA_SITE):
        await write_waf_site({})
        return {}
    return await read_json(PATH_WAF_LUA_SITE)


async def write_waf_site(config):
    """写入waf站点配置"""
    await write_json(PATH_WAF_LUA_SITE, config)
    return config


async def get_domain_sites():
    """获取所有站点的域名"""
    sites = []
    all_paths = await aio_walk(PATH_APP_ZDGL, pattern="domain.*?.conf")
    if not all_paths:
        return sites

    pattern_server_name = r"server_name\s+(.+?)\s*;"
    pattern_listen_port = r"listen\s+(.+?)\s*;"
    for file_path in all_paths:
        conf = await read_file(file_path)
        match_server_name = re_search(pattern_server_name, conf, re_I)
        if not match_server_name:
            continue
        domain_str = match_server_name.group(1).strip()
        if not domain_str:
            continue
        match_listen_port = re_search(pattern_listen_port, conf, re_I)
        listen_port = 80
        if match_listen_port:
            try:
                listen_port = int(match_listen_port.group(1).strip())
            except Exception:
                pass

        server_names = domain_str.split()
        server_names_set = list(set([f"{domain}:{listen_port}" for domain in server_names if "." in domain]))
        if not server_names_set:
            continue

        main_path = Path(file_path).parent.parent.joinpath("main.conf")
        site_name = ""
        if await aio_exists(main_path):
            main_conf = await read_file(main_path)
            match_site_name = re_search(r"#SITE_NAME:\s*(.*?);", main_conf, re_I)
            if match_site_name:
                site_name = match_site_name.group(1).strip()

        sites.append(
            {
                "name": f"{server_names[0]}:{listen_port}",
                "domain": server_names_set,
                "site_name": site_name,
                "listen_port": listen_port,
            }
        )

    return sites


async def read_site_domains():
    """读取所有站点的域名"""
    return await write_site_domains()


async def write_site_domains():
    """写入所有站点的域名"""
    sites = await get_domain_sites()
    my_domains = []
    for site in sites:
        my_domains.append(
            {
                "name": site["name"],
                "domains": site["domain"],
                "site_name": site["site_name"],
            }
        )

    await write_json(PATH_WAF_LUA_DOMAINS, my_domains)
    return my_domains
