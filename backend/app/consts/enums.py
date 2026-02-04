from enum import Enum, IntEnum


class StrEnum(str, Enum):

    def __str__(self) -> str:
        return self.name


class StrEnumBase(StrEnum):
    """字符串枚举基类"""

    @classmethod
    def get_allow(cls):
        """获取枚举值"""
        return [i.value for i in cls]


class IntEnumBase(IntEnum):
    """整数枚举基类"""

    @classmethod
    def get_allow(cls):
        """获取枚举值"""
        return [i.value for i in cls]


class IPTypeEnum(StrEnumBase):
    """IP类型"""

    ipv4 = "IPv4"
    ipv6 = "IPv6"


class RegTionsLxEnum(IntEnumBase):
    """地区限制类型"""

    reg = 1  # 地区限制
    city = 2  # 国内城市限制


class AckLogZtEnum(IntEnumBase):
    """攻击状态"""

    lj = 1  # 拦截
    zd = 2  # 阻断


class AckLogGjlxEnum(IntEnumBase):
    """攻击类型"""

    ip_black = 10001  # IP黑名单
    url_black = 10002  # URL黑名单
    ua_black = 10003  # UA黑名单
    reg_tions = 10004  # 区域限制
    error_404 = 10005  # 404
    hw_mode = 10006  # 护网模式
    fhgz_nday = 10007  # 专属规则
    fhgz_llxz = 10008  # 流量限制
    fhgz_diy_rule = 10009  # 自定义规则
    renji_black = 10010  # 人机黑名单

    conf_mod_def_url_cc = 10101  # URL级CC防御
    conf_mod_def_url_rjyz = 10102  # URL人机验证
    conf_mod_def_api_cc = 10103  # API级CC防御
    conf_mod_def_static_res = 10104  # 静态资源防御
    conf_mod_def_dir_scan = 10105  # 目录扫描防御
    conf_mod_def_robot = 10106  # 机器人防御
    conf_mod_def_http_req = 10107  # HTTP请求过滤
    conf_mod_def_gnw_fw = 10108  # 禁止国内外访问
    conf_mod_def_sql_inj = 10109  # 防SQL注入
    conf_mod_def_rce = 10110  # 防RCE攻击
    conf_mod_def_xss = 10111  # 防XSS攻击
    conf_mod_def_cookies = 10112  # 防Cookie攻击
    conf_mod_def_down = 10113  # 恶意下载防御
    conf_mod_def_url_bh = 10114  # URL保护防御
    conf_mod_def_upload = 10115  # 上传防御
    conf_mod_def_crawler = 10116  # 爬虫防御
    conf_mod_def_scan = 10117  # 扫描器防御
    conf_mod_def_resp_xytm = 10118  # 响应脱敏
    conf_mod_def_req_lj = 10119  # 请求链接


class RegAllowEnum(IntEnumBase):
    """拦截允许类型"""

    allow = 1  # 放行
    block = 2  # 拦截


class RuleAllowEnum(IntEnumBase):
    """规则允许类型"""

    allow = 1  # 白名单
    block = 2  # 黑名单


class RuleLxEnum(IntEnumBase):
    """规则类型"""

    ip = 1
    url = 2
    ua = 3
    renji = 4


class RespPageLxEnum(IntEnumBase):
    """响应页面类型"""

    jzwf = 1  # 禁止访问
    html404 = 2  # 网站不存在
    dqxz = 3  # 地区限制
    iphmd = 4  # ip黑名单


class SiderLxEnum(IntEnumBase):
    """爬虫类型"""

    baidu = 1  # 百度
    google = 2  # 谷歌
    _360 = 3  # 360
    sogou = 4  # 搜狗
    yahoo = 5  # yahoo
    bingbot = 6  # bingbot
    bytespider = 7  # bytespider
    shenma = 8  # 神马

    @classmethod
    def get_filename(cls):
        """获取枚举值"""
        return {
            cls.baidu: "baidu",
            cls.google: "google",
            cls._360: "_360",
            cls.sogou: "sogou",
            cls.yahoo: "yahoo",
            cls.bingbot: "bing",
            cls.bytespider: "bytespider",
            cls.shenma: "shenma",
        }


class ConfLxEnum(StrEnumBase):
    """配置分类类型"""

    def_url_cc = "def_url_cc"  # URL级CC防御
    def_url_rjyz = "def_url_rjyz"  # URL人机验证
    def_api_cc = "def_api_cc"  # API级CC防御
    def_static_res = "def_static_res"  # 静态资源防御
    def_dir_scan = "def_dir_scan"  # 目录扫描防御

    def_robot = "def_robot"  # 机器人防御
    def_http_req = "def_http_req"  # HTTP请求过滤
    def_gnw_fw = "def_gnw_fw"  # 禁止国内外访问

    def_sql_inj = "def_sql_inj"  # 防SQL注入
    def_rce = "def_rce"  # 防RCE攻击
    def_xss = "def_xss"  # 防XSS攻击
    def_cookies = "def_cookies"  # 防Cookie攻击

    def_down = "def_down"  # 恶意下载防御
    def_url_bh = "def_url_bh"  # URL保护防御
    def_upload = "def_upload"  # 上传防御

    def_crawler = "def_crawler"  # 爬虫防御
    def_scan = "def_scan"  # 扫描器防御

    def_resp_xytm = "def_resp_xytm"  # 响应脱敏
    def_req_lj = "def_req_lj"  # 请求敏感词拦截


class ConfFlEnum(StrEnumBase):
    """配置分类类型"""

    cc_def = "cc_def"  # 防CC攻击
    req_hg = "req_hg"  # 请求合规防御
    sql_def = "sql_def"  # 防SQL注入
    res_ly = "res_ly"  # 防资源滥用
    crawler = "crawler"  # 防自动化与爬虫
    mgc_word = "mgc_word"  # 敏感词

    @classmethod
    def get_conf(cls):
        """获取枚举值"""
        return {
            cls.cc_def: [
                ConfLxEnum.def_url_cc,
                ConfLxEnum.def_url_rjyz,
                ConfLxEnum.def_api_cc,
                ConfLxEnum.def_static_res,
                ConfLxEnum.def_dir_scan,
            ],
            cls.req_hg: [
                ConfLxEnum.def_robot,
                ConfLxEnum.def_http_req,
                ConfLxEnum.def_gnw_fw,
            ],
            cls.sql_def: [
                ConfLxEnum.def_sql_inj,
                ConfLxEnum.def_rce,
                ConfLxEnum.def_xss,
                ConfLxEnum.def_cookies,
            ],
            cls.res_ly: [
                ConfLxEnum.def_down,
                ConfLxEnum.def_url_bh,
                ConfLxEnum.def_upload,
            ],
            cls.crawler: [
                ConfLxEnum.def_crawler,
                ConfLxEnum.def_scan,
            ],
            cls.mgc_word: [
                ConfLxEnum.def_resp_xytm,
                ConfLxEnum.def_req_lj,
            ],
        }


class ConfLxXyymEnum(StrEnumBase):
    """可修改响应页面的类型"""

    @classmethod
    def get_allow(cls):
        """获取枚举值"""
        return [
            ConfLxEnum.def_sql_inj,
            ConfLxEnum.def_rce,
            ConfLxEnum.def_xss,
            ConfLxEnum.def_cookies,
            ConfLxEnum.def_down,
            ConfLxEnum.def_crawler,
            ConfLxEnum.def_scan,
        ]


class QsLogSjlxEnum(IntEnumBase):
    """QsLog表时间类型"""

    year = 1  # 年
    month = 2  # 月
    day = 3  # 日
    server_name_year = 11  # 站点名称年
    server_name_month = 12  # 站点名称月
    server_name_day = 13  # 站点名称日


class DefHttpReqQqlxEnum(StrEnumBase):
    """HTTP请求过滤 请求类型"""

    # 基础HTTP方法
    get = "GET"
    post = "POST"
    put = "PUT"
    delete = "DELETE"
    head = "HEAD"
    options = "OPTIONS"
    trace = "TRACE"
    connect = "CONNECT"

    # 扩展/特殊HTTP方法（前端展示的其他类型）
    patch = "PATCH"
    move = "MOVE"
    unlink = "UNLINK"
    proppatch = "PROPPATCH"
    search = "SEARCH"
    copy = "COPY"
    wrapped = "WRAPPED"
    mkcol = "MKCOL"
    link = "LINK"
    propfind = "PROPFIND"


class RuleFileLxEnum(StrEnumBase):
    """规则文件类型"""

    black = "rule_black"  # 黑名单
    white = "rule_white"  # 白名单


class FhgzFileLxEnum(StrEnumBase):
    """防护规则文件类型"""

    fhgz = "fhgz"  # 防护规则


class ConfModFileLxEnum(StrEnumBase):
    """全局配置文件类型"""

    qjcl = "conf_mod_qjcl"  # 全局策略
    sycl = "conf_mod_sycl"  # 站点策略
