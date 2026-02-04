"""模块表单"""

from simplejrpc import (
    BaseForm,
    BooleanField,
    DictField,
    IntegerField,
    IntegerRangeField,
    ListField,
    RequireValidator,
    StringField,
    StringRangField,
)
from simplejrpc import TextMessage as _

from app.consts.enums import ConfLxEnum, ConfLxXyymEnum


class PageBaseForm(BaseForm):
    """分页表单"""

    page = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    page_size = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefUrlCCForm(PageBaseForm):
    """获取URL级CC防御列表表单"""

    server_name = StringField()


class AddDefUrlCCForm(BaseForm):
    """添加URL级CC防御表单"""

    server_name = StringField()
    pp_mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    ms_mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fwsj = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    tjwd_ip = IntegerRangeField(allow=[0, 1], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fwcs = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    yzjb = IntegerRangeField(allow=[1, 2, 3, 4], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fssj = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fslx = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    xyym = IntegerRangeField(allow=[1, 2, 403, 404, 502, 503], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetDefUrlCCForm(BaseForm):
    """设置URL级CC防御表单"""

    server_name = StringField()
    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    pp_mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    ms_mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fwsj = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    tjwd_ip = IntegerRangeField(allow=[0, 1], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fwcs = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    yzjb = IntegerRangeField(allow=[1, 2, 3, 4], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fssj = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fslx = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    xyym = IntegerRangeField(allow=[1, 2, 403, 404, 502, 503], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DelDefUrlCCForm(BaseForm):
    """删除URL级CC防御表单"""

    server_name = StringField()
    uuid = ListField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefUrlRjyzForm(PageBaseForm):
    """获取URL人机验证列表表单"""

    server_name = StringField()


class AddDefUrlRjyzForm(BaseForm):
    """添加URL人机验证表单"""

    server_name = StringField()
    pp_mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    csz = ListField()
    yzfs = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetDefUrlRjyzForm(BaseForm):
    """设置URL人机验证表单"""

    server_name = StringField()
    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    pp_mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    csz = ListField()
    yzfs = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DelDefUrlRjyzForm(BaseForm):
    """删除URL人机验证表单"""

    server_name = StringField()
    uuid = ListField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefApiCCForm(PageBaseForm):
    """获取API CC防御列表表单"""

    server_name = StringField()


class AddDefApiCCForm(BaseForm):
    """添加API CC防御表单"""

    server_name = StringField()
    pp_mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fwsj = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    tjwd_ip = IntegerRangeField(allow=[0, 1], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fwcs = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fssj = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fslx = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetDefApiCCForm(BaseForm):
    """设置API CC防御表单"""

    server_name = StringField()
    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    pp_mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fwsj = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    tjwd_ip = IntegerRangeField(allow=[0, 1], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fwcs = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fssj = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fslx = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DelDefApiCCForm(BaseForm):
    """删除API CC防御表单"""

    server_name = StringField()
    uuid = ListField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefDirScanForm(BaseForm):
    """获取目录扫描防御配置表单"""

    server_name = StringField()


class SetDefDirScanForm(BaseForm):
    """设置目录扫描防御配置表单"""

    server_name = StringField()
    fwsj = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fwcs = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefHttpReqQqslForm(BaseForm):
    """获取HTTP请求过滤 请求数量过滤表单"""

    server_name = StringField()


class SetDefHttpReqQqslForm(BaseForm):
    """设置HTTP请求过滤 请求数量过滤表单"""

    server_name = StringField()
    jm_base64 = BooleanField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    cszdcd = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    post_cszdsl = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    get_cszdsl = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefHttpReqQqtForm(PageBaseForm):
    """获取HTTP请求过滤 请求头过滤表单"""

    server_name = StringField()


class AddDefHttpReqQqtForm(BaseForm):
    """添加HTTP请求过滤 请求头过滤表单"""

    server_name = StringField()
    qqt = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    dx = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetDefHttpReqQqtForm(BaseForm):
    """设置HTTP请求过滤 请求头过滤表单"""

    server_name = StringField()
    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    qqt = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    dx = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DelDefHttpReqQqtForm(BaseForm):
    """删除HTTP请求过滤 请求头过滤表单"""

    server_name = StringField()
    uuid = ListField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefHttpReqQqlxForm(PageBaseForm):
    """获取HTTP请求过滤 请求类型表单"""

    server_name = StringField()


class AddDefHttpReqQqlxForm(BaseForm):
    """添加HTTP请求过滤 请求类型表单"""

    server_name = StringField()
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    qqlx = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetDefHttpReqQqlxForm(BaseForm):
    """设置HTTP请求过滤 请求类型表单"""

    server_name = StringField()
    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    qqlx = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DelDefHttpReqQqlxForm(BaseForm):
    """删除HTTP请求过滤 请求类型表单"""

    server_name = StringField()
    uuid = ListField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefGnwFwForm(BaseForm):
    """获取禁止国内外访问表单"""

    server_name = StringField()
    lx = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetDefGnwFwForm(BaseForm):
    """设置禁止国内外访问表单"""

    server_name = StringField()
    lx = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    ip_list = ListField()
    xyym = IntegerRangeField(allow=[200, 403, 404, 500, 502, 503], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class ConfModForm(BaseForm):
    """获取配置表单"""

    server_name = StringField()


class ConfModOpenForm(BaseForm):
    """修改通用设置表单"""

    server_name = StringField()
    mod_name = StringRangField(allow=ConfLxEnum.get_allow(), validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetConfModForm(BaseForm):
    """修改通用设置"""

    server_name = StringField()
    mod_name = StringRangField(allow=ConfLxXyymEnum.get_allow(), validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    xyym = IntegerRangeField(allow=[200, 403, 404, 500, 502, 503], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DrConfModForm(BaseForm):
    """导入配置"""

    file_data = DictField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefSqlInjForm(PageBaseForm):
    """SQL注入防御表单"""

    server_name = StringField()


class DefSqlInjOpenForm(BaseForm):
    """SQL注入防御开启/关闭表单"""

    server_name = StringField()
    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefXssForm(PageBaseForm):
    """XSS注入防御表单"""

    server_name = StringField()


class DefXssOpenForm(BaseForm):
    """XSS注入防御开启/关闭表单"""

    server_name = StringField()
    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefCookiesForm(PageBaseForm):
    """Cookies防御表单"""

    server_name = StringField()


class DefCookiesOpenForm(BaseForm):
    """Cookies防御开启/关闭表单"""

    server_name = StringField()
    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class AddDefCookiesForm(BaseForm):
    """添加Cookies防御表单"""

    server_name = StringField()
    rule = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    remark = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetDefCookiesForm(BaseForm):
    """设置Cookies防御表单"""

    server_name = StringField()
    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    rule = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    remark = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DelDefCookiesForm(BaseForm):
    """删除Cookies防御表单"""

    server_name = StringField()
    uuid = ListField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefDownForm(BaseForm):
    """恶意下载防御表单"""

    server_name = StringField()


class DefDownOpenForm(BaseForm):
    """恶意下载防御开启/关闭表单"""

    server_name = StringField()
    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefUrlBhJzzxphpForm(BaseForm):
    """URL保护 禁止执行php表单"""

    server_name = StringField()


class SetDefUrlBhJzzxphpForm(BaseForm):
    """设置URL保护 禁止执行php表单"""

    server_name = StringField()
    url_list = ListField()


class DefUrlBhZdcsfwForm(PageBaseForm):
    """获取URL保护 指定参数访问表单"""

    server_name = StringField()


class AddDefUrlBhZdcsfwForm(BaseForm):
    """添加URL保护 指定参数访问表单"""

    server_name = StringField()
    pp_mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    csm = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    csz = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetDefUrlBhZdcsfwForm(BaseForm):
    """设置URL保护 指定参数访问表单"""

    server_name = StringField()
    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    pp_mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    csm = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    csz = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DelDefUrlBhZdcsfwForm(BaseForm):
    """删除URL保护 指定参数访问表单"""

    server_name = StringField()
    uuid = ListField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DefUploadForm(BaseForm):
    """获取恶意文件上传防御表单"""

    server_name = StringField()


class SetDefUploadForm(BaseForm):
    """设置恶意文件上传防御表单"""

    server_name = StringField()
    scgsyx = BooleanField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    jzsc = StringField()
    wjtjc = StringField()


class DefCrawlerForm(BaseForm):
    """获取恶意爬虫防御表单"""

    server_name = StringField()


class SetDefCrawlerForm(BaseForm):
    """设置恶意爬虫防御表单"""

    server_name = StringField()
    ua_list = ListField()


class DefScanForm(BaseForm):
    """获取恶意扫描器防御表单"""

    server_name = StringField()


class SetDefScanForm(BaseForm):
    """设置恶意扫描器防御表单"""

    server_name = StringField()
    header = ListField()
    cookie = ListField()
    args = ListField()


class DefRespXytmForm(BaseForm):
    """获取请求脱敏表单"""

    server_name = StringField()


class SetDefRespXytmForm(BaseForm):
    """设置请求脱敏表单"""

    server_name = StringField()
    mgxxjc = BooleanField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    mgwzth = ListField()


class DefReqLjWjcForm(BaseForm):
    """获取请求敏感词拦截 违禁词表单"""

    server_name = StringField()


class SetDefReqLjWjcForm(BaseForm):
    """设置请求敏感词拦截 违禁词表单"""

    server_name = StringField()
    wjc = ListField()


class DefReqLjUrlcsglForm(PageBaseForm):
    """获取请求敏感词拦截 URL级参数过滤表单"""

    server_name = StringField()


class AddDefReqLjUrlcsglForm(BaseForm):
    """添加请求敏感词拦截 URL级参数过滤表单"""

    server_name = StringField()
    pp_mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    gjc = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetDefReqLjUrlcsglForm(BaseForm):
    """设置请求敏感词拦截 URL级参数过滤表单"""

    server_name = StringField()
    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    pp_mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    gjc = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DelDefReqLjUrlcsglForm(BaseForm):
    """删除请求敏感词拦截 URL级参数过滤表单"""

    server_name = StringField()
    uuid = ListField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
