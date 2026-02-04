import re

from app.consts.settings import (
    PATH_APP_ZDGL,
    PATH_INSTALL_LOG,
    PATH_WAF_ENV_NGX_LUA_JSON_FILE,
    PATH_WAF_INSTALL_SUCCESS,
    PATH_WAF_LUA_CONFIG,
    PATH_WAF_OPEN_CONF,
    PATH_WAF_VERSION,
)
from app.utils.helpers import (
    GlobalException,
    aio_exists,
    exec_shell,
    read_file,
    read_json,
    write_file,
)
from app.utils.logger import logger
from app.utils.service import nginx_restart, read_waf_config


def _find_http_end(lines, start_line_idx):
    """
    从指定行开始，通过括号计数找到http块的闭合}行索引
    :param lines: 按行拆分的配置文本（保留换行符）
    :param start_line_idx: http {起始行索引
    :return: 闭合}的行索引，未找到返回-1
    """
    brace_count = 0
    for idx in range(start_line_idx, len(lines)):
        for char in lines[idx]:
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
                if brace_count == 0:
                    return idx
    return -1


def _add_safewaf_conf(conf_text):
    """
    核心函数：接收nginx配置文本，在http{}块末尾添加safewaf配置，返回修改后的文本
    :param conf_text: 原始nginx配置文本
    :return: 修改后的配置文本（未修改/修改失败返回原文本）
    """
    # 定义要添加的配置行（8空格缩进，符合nginx规范）
    safewaf_line = f"    include {PATH_WAF_OPEN_CONF};\n"
    safewaf_clean = safewaf_line.strip()

    # 防重复添加：已存在则直接返回原文本
    if safewaf_clean in conf_text:
        return conf_text

    # 按行拆分（保留换行符，保证格式不变）
    lines = conf_text.splitlines(keepends=True)

    # 正则匹配http{（兼容任意空格/换行，re.S等价于re.DOTALL）
    http_pattern = re.compile(r"http\s*\{", re.S)
    match = http_pattern.search(conf_text)
    if not match:
        return conf_text

    # 定位匹配位置对应的行索引
    match_start = match.start()
    char_count = 0
    http_start_idx = 0
    for idx, line in enumerate(lines):
        char_count += len(line)
        if char_count > match_start:
            http_start_idx = idx
            break

    # 找到http块闭合}
    http_end_idx = _find_http_end(lines, http_start_idx)
    if http_end_idx == -1:
        return conf_text

    # 插入配置行
    lines.insert(http_end_idx, safewaf_line)
    return "".join(lines)


async def check_safewaf_open(nginx_conf):
    """检查safewaf是否开启"""
    if not await aio_exists(nginx_conf):
        logger.error(f"没有找到nginx conf: {nginx_conf}")
        return False
    raw_text = await read_file(nginx_conf)
    safewaf_line = f"include {PATH_WAF_OPEN_CONF};"
    if safewaf_line in raw_text:
        return True
    return False


async def add_safewaf_conf(nginx_conf):
    """添加safewaf配置"""
    if not await aio_exists(nginx_conf):
        logger.error(f"没有找到nginx conf: {nginx_conf}")
        return False
    if await check_safewaf_open(nginx_conf):
        logger.info(f"nginx conf: {nginx_conf} 已开启safewaf, 无需添加")
        return True
    raw_text = await read_file(nginx_conf)
    new_text = _add_safewaf_conf(raw_text)
    await write_file(nginx_conf, new_text)
    return True


async def del_safewaf_conf(nginx_conf):
    """删除safewaf配置"""
    if not await aio_exists(nginx_conf):
        logger.error(f"没有找到nginx conf: {nginx_conf}")
        return False
    await exec_shell(f'sed -i "/lua_package_path/d" {nginx_conf}')
    await exec_shell(rf'sed -i "/include \/www\/server\/safewaf\/env\/open_conf\/safewaf.conf;/d" {nginx_conf}')


async def get_nginx_conf():
    """获取nginx配置"""
    flag, msg = await exec_shell("ps -ef|grep nginx|grep conf")
    if not flag:
        await nginx_restart()
        flag, msg = await exec_shell("ps -ef|grep nginx|grep conf")
        if not flag:
            raise GlobalException("OPEN_FAIl_NGINX_NOT_RUN")
    res = re.findall(r"-c\s*(\/\S+)", msg)
    if res:
        return res[0]
    conf_list = ["/www/server/nginx/conf/nginx.conf", "/etc/nginx/nginx.conf"]
    for conf in conf_list:
        if await aio_exists(conf):
            return conf
    return "/etc/nginx/nginx.conf"


async def check_zdgl_open():
    """检查站点管理是否运行"""
    if not await aio_exists(PATH_APP_ZDGL):
        return False

    nginx_conf = await get_nginx_conf()
    if not await aio_exists(nginx_conf):
        return False
    content = await read_file(nginx_conf)
    if PATH_APP_ZDGL not in content:
        return False
    return True


async def check_nginx_run():
    """检查nginx是否运行"""
    flag, msg = await exec_shell(r"ps -ef | \grep nginx | \grep -v grep|wc -l")
    if not flag:
        return False
    if int(msg.strip()) > 1:
        return True
    await nginx_restart()
    flag, msg = await exec_shell(r"ps -ef | \grep nginx | \grep -v grep|wc -l")
    if not flag:
        return False
    if int(msg.strip()) > 1:
        return True
    return False


async def raise_nginx_run():
    """检查nginx是否运行, 未运行则抛出异常"""
    if not await check_nginx_run():
        raise GlobalException("NGINX_NOT_RUN", code=-400)


async def check_need_up_install():
    """检查是否需要升级WAF"""
    if await aio_exists(PATH_WAF_VERSION):
        return False
    need_up_install = False
    dc_ver = await read_file(PATH_WAF_VERSION)
    zx_ver = await read_file("./app/static/VERSION")
    dc_ver, zx_ver = dc_ver.strip(), zx_ver.strip()
    logger.info(f"底层版本: {dc_ver}, WEB接口版本: {zx_ver}")
    if dc_ver.isdigit() and zx_ver.isdigit():
        need_up_install = int(dc_ver) < int(zx_ver)
        logger.info(f"需要升级WAF, 更新状态1: {need_up_install}")
    else:
        need_up_install = dc_ver != zx_ver
        logger.info(f"需要升级WAF, 更新状态2: {need_up_install}")
    return need_up_install


async def check_nginx_nochange():
    """检查nginx是否有变更"""
    flag, msg = await exec_shell("nginx -v")
    if not flag:
        return True
    dc_ngx_ver = await read_file(PATH_WAF_INSTALL_SUCCESS)
    dc_ngx_ver, zx_ngx_ver = dc_ngx_ver.strip(), msg.strip()
    logger.info(f"旧nginx版本: {dc_ngx_ver}, 新nginx版本: {zx_ngx_ver}")
    return dc_ngx_ver == zx_ngx_ver


async def check_nginx_state():
    """检查nginx是否支持safewaf"""
    flag, msg = await exec_shell("nginx -V")
    if not flag:
        return False
    if flag and "ngx_devel_kit" in msg and "lua_nginx_module" in msg:
        return True

    # 检测是否可以引入模块
    flag, msg = await exec_shell("uname -m")
    if not flag:
        return False
    if "aarch64" in msg:
        return False
    if "arm64" in msg:
        return False
    flag, msg = await exec_shell("nginx -v 2>&1 | grep -o '[[:digit:]].*$'")
    if not flag:
        return False

    nginx_ver = re.findall(r"\d+\.\d+\.\d+", msg)
    if not nginx_ver:
        logger.error(f"获取nginx版本失败: {msg}")
        return False
    nginx_ver = nginx_ver[0]
    os_ngx = f"nginx{nginx_ver}"
    logger.info(f"os_ngx: {os_ngx}")

    ngx_json = await read_json(PATH_WAF_ENV_NGX_LUA_JSON_FILE)
    if not ngx_json:
        logger.error(f"读取 {PATH_WAF_ENV_NGX_LUA_JSON_FILE} 失败")
        return False
    ngx_list = ngx_json.get("ngx_list", [])
    if os_ngx in ngx_list:
        return True

    logger.error(f"{os_ngx} 不支持的nginx版本")
    return False


async def check_waf_state():
    """检查waf模块状态"""
    flag, msg = await exec_shell("/usr/local/bin/luajit -v")
    if not flag:
        logger.error(msg)
        return False
    flag, msg = await exec_shell("/usr/local/bin/luajit -e \"require 'lsqlite3'\"")
    if not flag:
        logger.error(msg)
        return False
    flag, msg = await exec_shell("/usr/local/bin/luajit -e \"require 'cjson'\"")
    if not flag:
        logger.error(msg)
        return False
    return True
