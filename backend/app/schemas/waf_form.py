"""waf表单"""

from simplejrpc import (
    BaseForm,
    BooleanField,
    DictField,
    IntegerField,
    IntegerRangeField,
    ListField,
    RequireValidator,
    StringField,
)
from simplejrpc import TextMessage as _

from app.consts.enums import (
    AckLogGjlxEnum,
    AckLogZtEnum,
    RegAllowEnum,
    RegTionsLxEnum,
    RespPageLxEnum,
    RuleAllowEnum,
    RuleLxEnum,
    SiderLxEnum,
)


class PageBaseForm(BaseForm):
    """分页表单"""

    page = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    page_size = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class GlLogsForm(PageBaseForm):
    """获取管理日志表单"""

    pass


class ConfigSetOpenForm(BaseForm):
    """开启/关闭全局配置"""

    name = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class CdnSzSetForm(BaseForm):
    """设置CDN设置表单"""

    open = BooleanField()
    mode = IntegerRangeField(allow=[1, 2, 3])
    http_header = StringField()
    http_headers = StringField()
    x_forwarded_for = StringField()


class AckLogForm(PageBaseForm):
    """获取攻击日志表单"""

    name = StringField()
    start_time = StringField()
    end_time = StringField()
    zt = IntegerRangeField(allow=AckLogZtEnum.get_allow())
    gjlx = IntegerRangeField(allow=AckLogGjlxEnum.get_allow())
    server_name = StringField()


class AckLogXqForm(BaseForm):
    """获取攻击日志详情表单"""

    path = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class BlockingLogForm(PageBaseForm):
    """获取阻断日志表单"""

    pass


class SitesConfForm(PageBaseForm):
    """获取站点配置表单"""

    name = StringField()
    open = BooleanField()


class SiteSetOpenForm(BaseForm):
    """开启/关闭站点WAF表单"""

    name = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SiteSetModeForm(BaseForm):
    """设置站点WAF策略模式表单"""

    name = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class RegTionsForm(PageBaseForm):
    """获取地区限制表单"""

    pass


class AddRegTionForm(BaseForm):
    """添加地区限制表单"""

    allow = IntegerRangeField(allow=RegAllowEnum.get_allow(), validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    name = StringField()
    region = StringField()
    city = StringField()


class SetRegTionForm(BaseForm):
    """设置地区限制表单"""

    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    allow = IntegerRangeField(allow=RegAllowEnum.get_allow(), validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    name = StringField()
    region = StringField()
    city = StringField()


class DelRegTionForm(BaseForm):
    """删除地区限制表单"""

    uuid = ListField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetRegTionOpenForm(BaseForm):
    """设置地区限制开启/关闭表单"""

    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class RuleForm(PageBaseForm):
    """获取规则表单"""

    allow = IntegerRangeField(allow=RuleAllowEnum.get_allow(), validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    name = StringField()
    lx = IntegerRangeField(allow=RuleLxEnum.get_allow())


class AddRuleForm(BaseForm):
    """添加规则表单"""

    allow = IntegerRangeField(allow=RuleAllowEnum.get_allow(), validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    lx = IntegerRangeField(allow=RuleLxEnum.get_allow(), validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    wb = StringField()
    remark = StringField()


class SetRuleForm(BaseForm):
    """设置规则表单"""

    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    wb = StringField()
    remark = StringField()


class SetRuleRemarkForm(BaseForm):
    """设置规则备注表单"""

    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    remark = StringField()


class DcRuleForm(BaseForm):
    """导出规则表单"""

    allow = IntegerRangeField(allow=RuleAllowEnum.get_allow(), validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DrRuleForm(BaseForm):
    """设置规则备注表单"""

    file_data = DictField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DelRuleForm(BaseForm):
    """添加规则表单"""

    uuid = ListField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class RespPageForm(BaseForm):
    """获取响应页面表单"""

    lx = IntegerRangeField(allow=RespPageLxEnum.get_allow(), validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SiderLxForm(BaseForm):
    """获取爬虫类型表单"""

    lx = IntegerRangeField(allow=SiderLxEnum.get_allow(), validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetSiderLxForm(BaseForm):
    """获取爬虫类型表单"""

    lx = IntegerRangeField(allow=SiderLxEnum.get_allow(), validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    ip_list = ListField()


class L3RuleForm(BaseForm):
    """设置L3规则表单"""

    ip = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetDDWebhookForm(BaseForm):
    """设置钉钉告警Webhook表单"""

    open = BooleanField()
    url = StringField()
    secret = StringField()


class SetHTTPWebhookForm(BaseForm):
    """设置HTTP告警Webhook表单"""

    open = BooleanField()
    url = StringField()


class TodayTop10Form(BaseForm):
    """获取今日top10表单"""

    server_name = StringField()


class HomeTjForm(BaseForm):
    """获取首页数据统计表单"""

    server_name = StringField()


class HomeSsljForm(BaseForm):
    """获取首页实时拦截表单"""

    server_name = StringField()
    sjlx = IntegerRangeField(allow=[1, 2])  # 1分钟 2小时


class HomeLsljForm(BaseForm):
    """获取首页历史拦截表单"""

    server_name = StringField()
    lx = IntegerRangeField(allow=[1, 2, 3])  # 1年 2月 3日


class FhgzLlxzForm(PageBaseForm):
    """获取防护规则_流量限制表单"""

    pass


class AddFhgzLlxzForm(BaseForm):
    """添加防护规则_流量限制表单"""

    rule_name = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    name = StringField()
    mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    wd = IntegerRangeField(allow=[1, 2, 3], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    plsj = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    pljc = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    xydz = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    xyym = IntegerRangeField(allow=[403, 404, 502, 503], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fhgs = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetFhgzLlxzForm(BaseForm):
    """设置防护规则_流量限制表单"""

    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    rule_name = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    name = StringField()
    mode = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    url = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    wd = IntegerRangeField(allow=[1, 2, 3], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    plsj = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    pljc = IntegerField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    xydz = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    xyym = IntegerRangeField(allow=[403, 404, 502, 503], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    fhgs = IntegerRangeField(allow=[1, 2], validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetFhgzLlxzOpenForm(BaseForm):
    """设置防护规则_流量限制开启/关闭表单"""

    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DelFhgzLlxzForm(BaseForm):
    """删除防护规则_流量限制表单"""

    uuid = ListField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetFhgzNdayOpenForm(BaseForm):
    """设置防护规则_专属规则开启/关闭表单"""

    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class FhgzDiyRuleForm(PageBaseForm):
    """获取防护规则_自定义规则表单"""

    pass


class AddFhgzDiyRuleForm(BaseForm):
    """添加防护规则_自定义规则表单"""

    rule_name = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    name = StringField()
    action = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    action_type = StringField()
    # rule = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetFhgzDiyRuleForm(BaseForm):
    """设置防护规则_自定义规则表单"""

    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    rule_name = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    name = StringField()
    action = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
    action_type = StringField()
    # rule = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class SetFhgzDiyRuleOpenForm(BaseForm):
    """设置防护规则_自定义规则开启/关闭表单"""

    uuid = StringField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DelFhgzDiyRuleForm(BaseForm):
    """删除防护规则_自定义规则表单"""

    uuid = ListField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])


class DrFhgzForm(BaseForm):
    """导入防护规则表单"""

    file_data = DictField(validators=[RequireValidator(_("REQUIRE_VALIDATION_TM"))])
