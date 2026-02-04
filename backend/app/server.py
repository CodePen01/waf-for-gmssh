"""WAF接口"""

from simplejrpc.app import ServerApplication
from simplejrpc.i18n import T as i18n
from simplejrpc.response import jsonify

from app.consts.settings import (
    APP_CONFIG_FILE_PATH,
    APP_I18N_DIR_PATH,
    APP_SOCKET_FILE_PATH,
)
from app.middlewares.example import ExampleMiddleware
from app.schemas import mod_form, waf_form
from app.services.conf_mod.cc_def.def_api_cc import DefApiCC
from app.services.conf_mod.cc_def.def_dir_scan import DefDirScan
from app.services.conf_mod.cc_def.def_url_cc import DefUrlCC
from app.services.conf_mod.cc_def.def_url_rjyz import DefUrlRjyz
from app.services.conf_mod.conf_mod import ConfMod
from app.services.conf_mod.crawler.def_crawler import DefCrawler
from app.services.conf_mod.crawler.def_scan import DefScan
from app.services.conf_mod.mgc_word.def_req_lj import DefReqLj
from app.services.conf_mod.mgc_word.def_resp_xytm import DefRespXytm
from app.services.conf_mod.req_hg.def_gnw_fw import DefGnwFw
from app.services.conf_mod.req_hg.def_http_req import (
    DefHttpReqQqlx,
    DefHttpReqQqsl,
    DefHttpReqQqt,
)
from app.services.conf_mod.res_ly.def_down import DefDown
from app.services.conf_mod.res_ly.def_upload import DefUpload
from app.services.conf_mod.res_ly.def_url_bh import DefUrlBh
from app.services.conf_mod.sql_def.def_cookies import DefCookies
from app.services.conf_mod.sql_def.def_sql_inj import DefSqlInj
from app.services.conf_mod.sql_def.def_xss import DefXss
from app.services.conf_sites import SitesConf
from app.services.conf_waf import WafConf
from app.services.fh_rule import FhgzDiyRule, FhgzLlxz, FhgzNday, FhgzUtils
from app.services.home import Home
from app.services.l3_rule import L3Rule
from app.services.region import Region
from app.services.rule import Rule
from app.services.spider import Spider
from app.services.waf import Waf
from app.services.webhook import WebHook

app = ServerApplication(
    socket_path=APP_SOCKET_FILE_PATH,
    i18n_dir=APP_I18N_DIR_PATH,
    config_path=APP_CONFIG_FILE_PATH,
)
app.middleware(ExampleMiddleware())


@app.route(name="hello")
async def hello(**kwargs):
    """测试用例"""
    return jsonify(data="hello world", msg=i18n.translate("STATUS_OK"))


# 状态检查接口
@app.route(name="ping")
async def ping(**kwargs):
    """呼吸包"""
    return jsonify(data="pong", msg=i18n.translate("STATUS_OK"))


@app.route(name="get_open")
async def get_open(**kwargs):
    """获取WAF开启状态"""
    waf_conf = WafConf()
    data = await waf_conf.get_open(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_open")
async def set_open(**kwargs):
    """开启/关闭WAF"""
    waf = Waf()
    data = await waf.set_open(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="install_waf")
async def install_waf(**kwargs):
    """安装WAF"""
    waf = Waf()
    data = await waf.install_waf(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_config")
async def get_config(**kwargs):
    """获取全局配置"""
    waf_conf = WafConf()
    data = await waf_conf.get_config()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_hw_mode")
async def get_hw_mode(**kwargs):
    """获取护网模式"""
    waf_conf = WafConf()
    data = await waf_conf.get_hw_mode()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_hw_mode_open")
async def set_hw_mode_open(**kwargs):
    """开启/关闭护网模式"""
    waf_conf = WafConf()
    data = await waf_conf.set_hw_mode_open()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_cdn_sz")
async def get_cdn_sz(**kwargs):
    """获取CDN设置"""
    waf_conf = WafConf()
    data = await waf_conf.get_cdn_sz()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_cdn_sz", form=waf_form.CdnSzSetForm)
async def set_cdn_sz(**kwargs):
    """设置CDN设置"""
    waf_conf = WafConf()
    data = await waf_conf.set_cdn_sz(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="reset_config")
async def reset_config(**kwargs):
    """还原全局配置"""
    waf_conf = WafConf()
    data = await waf_conf.reset_config(nginx_restart_flag=True)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


# @app.route(name="set_config_open", form=waf_form.ConfigSetOpenForm)
# async def set_config_open(**kwargs):
#     """开启/关闭全局配置"""
#     waf_conf = WafConf()
#     data = await waf_conf.set_config_open(kwargs)
#     return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_all_sites")
async def get_all_sites(**kwargs):
    """获取全部站点"""
    site_conf = SitesConf()
    data = await site_conf.get_all_sites()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_sites_conf", form=waf_form.SitesConfForm)
async def get_sites_conf(**kwargs):
    """获取站点配置"""
    site_conf = SitesConf()
    data = await site_conf.get_sites_conf(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="tb_sites")
async def tb_sites(**kwargs):
    """站点同步"""
    site_conf = SitesConf()
    data = await site_conf.tb_sites(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_site_open", form=waf_form.SiteSetOpenForm)
async def set_site_open(**kwargs):
    """开启/关闭站点WAF"""
    site_conf = SitesConf()
    data = await site_conf.set_site_open(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_site_mode", form=waf_form.SiteSetModeForm)
async def set_site_mode(**kwargs):
    """设置站点WAF策略模式"""
    site_conf = SitesConf()
    data = await site_conf.set_site_mode(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


# @app.route(name="get_gl_logs", form=waf_form.GlLogsForm)
# async def get_gl_logs(**kwargs):
#     """获取管理日志"""
#     waf = Waf()
#     data = await waf.get_gl_logs(kwargs)
#     return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_ack_logs", form=waf_form.AckLogForm)
async def get_ack_logs(**kwargs):
    """获取攻击日志"""
    waf = Waf()
    data = await waf.get_ack_logs(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_ack_gjlx")
async def get_ack_gjlx(**kwargs):
    """获取攻击类型"""
    waf = Waf()
    data = await waf.get_ack_gjlx()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_ack_logxq", form=waf_form.AckLogXqForm)
async def get_ack_logxq(**kwargs):
    """获取攻击日志详情"""
    waf = Waf()
    data = await waf.get_ack_logxq(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_reg_tions", form=waf_form.RegTionsForm)
async def get_reg_tions(**kwargs):
    """获取地区限制"""
    region = Region()
    data = await region.get_reg_tions(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="add_reg_tion", form=waf_form.AddRegTionForm)
async def add_reg_tion(**kwargs):
    """添加地区限制"""
    region = Region()
    data = await region.add_reg_tion(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_reg_tion", form=waf_form.SetRegTionForm)
async def set_reg_tion(**kwargs):
    """设置地区限制"""
    region = Region()
    data = await region.set_reg_tion(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="del_reg_tion", form=waf_form.DelRegTionForm)
async def del_reg_tion(**kwargs):
    """删除地区限制"""
    region = Region()
    data = await region.del_reg_tion(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_reg_tion_open", form=waf_form.SetRegTionOpenForm)
async def set_reg_tion_open(**kwargs):
    """设置地区限制开启/关闭"""
    region = Region()
    data = await region.set_reg_tion_open(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_rule", form=waf_form.RuleForm)
async def get_rule(**kwargs):
    """获取规则"""
    rule = Rule()
    data = await rule.get_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="add_rule", form=waf_form.AddRuleForm)
async def add_rule(**kwargs):
    """添加规则"""
    rule = Rule()
    data = await rule.add_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_rule", form=waf_form.SetRuleForm)
async def set_rule(**kwargs):
    """设置规则"""
    rule = Rule()
    data = await rule.set_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="del_rule", form=waf_form.DelRuleForm)
async def del_rule(**kwargs):
    """删除规则"""
    rule = Rule()
    data = await rule.del_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_rule_remark", form=waf_form.SetRuleRemarkForm)
async def set_rule_remark(**kwargs):
    """设置规则备注"""
    rule = Rule()
    data = await rule.set_rule_remark(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="dc_rule", form=waf_form.DcRuleForm)
async def dc_rule(**kwargs):
    """导出规则"""
    rule = Rule()
    data = await rule.dc_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="dr_rule", form=waf_form.DrRuleForm)
async def dr_rule(**kwargs):
    """导入规则"""
    rule = Rule()
    data = await rule.dr_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_resp_page", form=waf_form.RespPageForm)
async def get_resp_page(**kwargs):
    """获取响应页面"""
    waf = Waf()
    data = await waf.get_resp_page(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_spider_ip", form=waf_form.SiderLxForm)
async def get_spider_ip(**kwargs):
    """获取爬虫类型"""
    spider = Spider()
    data = await spider.get_spider_ip(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_spider_ip", form=waf_form.SetSiderLxForm)
async def set_spider_ip(**kwargs):
    """蜘蛛IP保存"""
    spider = Spider()
    data = await spider.set_spider_ip(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_l3_rule")
async def get_l3_rule(**kwargs):
    """获取L3规则"""
    l3 = L3Rule()
    data = await l3.get_l3_rule()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="add_l3_rule", form=waf_form.L3RuleForm)
async def add_l3_rule(**kwargs):
    """添加L3规则"""
    l3 = L3Rule()
    data = await l3.add_l3_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="del_l3_rule", form=waf_form.L3RuleForm)
async def del_l3_rule(**kwargs):
    """删除L3规则"""
    l3 = L3Rule()
    data = await l3.del_l3_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="clear_l3_rule")
async def clear_l3_rule(**kwargs):
    """清空L3规则"""
    l3 = L3Rule()
    data = await l3.clear_l3_rule()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_ack_webhook")
async def get_ack_webhook(**kwargs):
    """获取攻击告警Webhook"""
    whk = WebHook()
    data = await whk.get_ack_webhook()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_dd_webhook", form=waf_form.SetDDWebhookForm)
async def set_dd_webhook(**kwargs):
    """设置钉钉告警Webhook"""
    whk = WebHook()
    data = await whk.set_dd_webhook(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="test_dd_webhook")
async def test_dd_webhook(**kwargs):
    """测试钉钉告警Webhook"""
    whk = WebHook()
    data = await whk.test_dd_webhook()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_http_webhook", form=waf_form.SetHTTPWebhookForm)
async def set_http_webhook(**kwargs):
    """设置HTTP告警Webhook"""
    whk = WebHook()
    data = await whk.set_http_webhook(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="test_http_webhook")
async def test_http_webhook(**kwargs):
    """测试HTTP告警Webhook"""
    whk = WebHook()
    data = await whk.test_http_webhook()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_today_gjlx_top10", form=waf_form.TodayTop10Form)
async def get_today_gjlx_top10(**kwargs):
    """获取今日拦截类型top10"""
    home = Home()
    data = await home.get_today_gjlx_top10(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_today_ip_top10", form=waf_form.TodayTop10Form)
async def get_today_ip_top10(**kwargs):
    """获取今日拦截IPtop10"""
    home = Home()
    data = await home.get_today_ip_top10(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_today_url_top10", form=waf_form.TodayTop10Form)
async def get_today_url_top10(**kwargs):
    """获取今日拦截URLtop10"""
    home = Home()
    data = await home.get_today_url_top10(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_home_tj", form=waf_form.HomeTjForm)
async def get_home_tj(**kwargs):
    """获取首页数据统计"""
    home = Home()
    data = await home.get_home_tj(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_home_qq_sslj", form=waf_form.HomeSsljForm)
async def get_home_qq_sslj(**kwargs):
    """获取首页实时拦截_请求量"""
    home = Home()
    data = await home.get_home_qq_sslj(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_home_tt_sslj", form=waf_form.HomeSsljForm)
async def get_home_tt_sslj(**kwargs):
    """获取首页实时拦截_吞吐量"""
    home = Home()
    data = await home.get_home_tt_sslj(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_home_lslj", form=waf_form.HomeLsljForm)
async def get_home_lslj(**kwargs):
    """获取首页历史拦截_请求量"""
    home = Home()
    data = await home.get_home_lslj(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_fhgz_llxz", form=waf_form.FhgzLlxzForm)
async def get_fhgz_llxz(**kwargs):
    """获取防护规则_流量限制"""
    fh_llxz = FhgzLlxz()
    data = await fh_llxz.get_fhgz_llxz(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="add_fhgz_llxz", form=waf_form.AddFhgzLlxzForm)
async def add_fhgz_llxz(**kwargs):
    """添加防护规则_流量限制"""
    fh_llxz = FhgzLlxz()
    data = await fh_llxz.add_fhgz_llxz(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_fhgz_llxz", form=waf_form.SetFhgzLlxzForm)
async def set_fhgz_llxz(**kwargs):
    """设置防护规则_流量限制"""
    fh_llxz = FhgzLlxz()
    data = await fh_llxz.set_fhgz_llxz(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_fhgz_llxz_open", form=waf_form.SetFhgzLlxzOpenForm)
async def set_fhgz_llxz_open(**kwargs):
    """设置防护规则_流量限制开启/关闭"""
    fh_llxz = FhgzLlxz()
    data = await fh_llxz.set_fhgz_llxz_open(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="del_fhgz_llxz", form=waf_form.DelFhgzLlxzForm)
async def del_fhgz_llxz(**kwargs):
    """删除防护规则_流量限制"""
    fh_llxz = FhgzLlxz()
    data = await fh_llxz.del_fhgz_llxz(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_fhgz_nday")
async def get_fhgz_nday(**kwargs):
    """获取防护规则_专属规则"""
    fh_nday = FhgzNday()
    data = await fh_nday.get_fhgz_nday(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_fhgz_nday_open", form=waf_form.SetFhgzNdayOpenForm)
async def set_fhgz_nday_open(**kwargs):
    """设置防护规则_专属规则开启/关闭"""
    fh_nday = FhgzNday()
    data = await fh_nday.set_fhgz_nday_open(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_fhgz_diy_rule", form=waf_form.FhgzDiyRuleForm)
async def get_fhgz_diy_rule(**kwargs):
    """获取防护规则_自定义规则"""
    fh_diy = FhgzDiyRule()
    data = await fh_diy.get_fhgz_diy_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_fhgz_diy_rule_addconf")
async def get_fhgz_diy_rule_addconf(**kwargs):
    """获取防护规则_自定义规则"""
    fh_diy = FhgzDiyRule()
    data = await fh_diy.get_fhgz_diy_rule_addconf(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="add_fhgz_diy_rule", form=waf_form.AddFhgzDiyRuleForm)
async def add_fhgz_diy_rule(**kwargs):
    """添加防护规则_自定义规则"""
    fh_diy = FhgzDiyRule()
    data = await fh_diy.add_fhgz_diy_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_fhgz_diy_rule", form=waf_form.SetFhgzDiyRuleForm)
async def set_fhgz_diy_rule(**kwargs):
    """设置防护规则_自定义规则"""
    fh_diy = FhgzDiyRule()
    data = await fh_diy.set_fhgz_diy_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_fhgz_diy_rule_open", form=waf_form.SetFhgzDiyRuleOpenForm)
async def set_fhgz_diy_rule_open(**kwargs):
    """设置防护规则_自定义规则开启/关闭"""
    fh_diy = FhgzDiyRule()
    data = await fh_diy.set_fhgz_diy_rule_open(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="del_fhgz_diy_rule", form=waf_form.DelFhgzDiyRuleForm)
async def del_fhgz_diy_rule(**kwargs):
    """删除防护规则_自定义规则"""
    fh_diy = FhgzDiyRule()
    data = await fh_diy.del_fhgz_diy_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="dc_fhgz")
async def dc_fhgz(**kwargs):
    """导出防护规则"""
    api = FhgzUtils()
    data = await api.dc_fhgz()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="dr_fhgz", form=waf_form.DrFhgzForm)
async def dr_fhgz(**kwargs):
    """导入防护规则"""
    api = FhgzUtils()
    data = await api.dr_fhgz(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_url_cc", form=mod_form.DefUrlCCForm)
async def get_mod_def_url_cc(**kwargs):
    """获取URL级CC防御列表"""
    api = DefUrlCC()
    data = await api.get_mod_def_url_cc(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="add_mod_def_url_cc", form=mod_form.AddDefUrlCCForm)
async def add_mod_def_url_cc(**kwargs):
    """添加URL级CC防御"""
    api = DefUrlCC()
    data = await api.add_mod_def_url_cc(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_url_cc", form=mod_form.SetDefUrlCCForm)
async def set_mod_def_url_cc(**kwargs):
    """设置URL级CC防御"""
    api = DefUrlCC()
    data = await api.set_mod_def_url_cc(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="del_mod_def_url_cc", form=mod_form.DelDefUrlCCForm)
async def del_mod_def_url_cc(**kwargs):
    """删除URL级CC防御"""
    api = DefUrlCC()
    data = await api.del_mod_def_url_cc(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_url_rjyz", form=mod_form.DefUrlRjyzForm)
async def get_mod_def_url_rjyz(**kwargs):
    """获取URL人机验证列表"""
    api = DefUrlRjyz()
    data = await api.get_mod_def_url_rjyz(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="add_mod_def_url_rjyz", form=mod_form.AddDefUrlRjyzForm)
async def add_mod_def_url_rjyz(**kwargs):
    """添加URL人机验证"""
    api = DefUrlRjyz()
    data = await api.add_mod_def_url_rjyz(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_url_rjyz", form=mod_form.SetDefUrlRjyzForm)
async def set_mod_def_url_rjyz(**kwargs):
    """设置URL人机验证"""
    api = DefUrlRjyz()
    data = await api.set_mod_def_url_rjyz(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="del_mod_def_url_rjyz", form=mod_form.DelDefUrlRjyzForm)
async def del_mod_def_url_rjyz(**kwargs):
    """删除URL人机验证"""
    api = DefUrlRjyz()
    data = await api.del_mod_def_url_rjyz(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_api_cc", form=mod_form.DefApiCCForm)
async def get_mod_def_api_cc(**kwargs):
    """获取API CC防御列表"""
    api = DefApiCC()
    data = await api.get_mod_def_api_cc(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="add_mod_def_api_cc", form=mod_form.AddDefApiCCForm)
async def add_mod_def_api_cc(**kwargs):
    """添加API CC防御"""
    api = DefApiCC()
    data = await api.add_mod_def_api_cc(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_api_cc", form=mod_form.SetDefApiCCForm)
async def set_mod_def_api_cc(**kwargs):
    """设置API CC防御"""
    api = DefApiCC()
    data = await api.set_mod_def_api_cc(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="del_mod_def_api_cc", form=mod_form.DelDefApiCCForm)
async def del_mod_def_api_cc(**kwargs):
    """删除API CC防御"""
    api = DefApiCC()
    data = await api.del_mod_def_api_cc(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_dir_scan", form=mod_form.DefDirScanForm)
async def get_mod_def_dir_scan(**kwargs):
    """获取目录扫描防御配置"""
    api = DefDirScan()
    data = await api.get_mod_def_dir_scan(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_dir_scan", form=mod_form.SetDefDirScanForm)
async def set_mod_def_dir_scan(**kwargs):
    """设置目录扫描防御配置"""
    api = DefDirScan()
    data = await api.set_mod_def_dir_scan(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_http_req_qqsl", form=mod_form.DefHttpReqQqslForm)
async def get_mod_def_http_req_qqsl(**kwargs):
    """获取HTTP请求过滤 请求数量过滤"""
    api = DefHttpReqQqsl()
    data = await api.get_mod_def_http_req_qqsl(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_http_req_qqsl", form=mod_form.SetDefHttpReqQqslForm)
async def set_mod_def_http_req_qqsl(**kwargs):
    """设置HTTP请求过滤 请求数量过滤"""
    api = DefHttpReqQqsl()
    data = await api.set_mod_def_http_req_qqsl(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_http_req_qqt", form=mod_form.DefHttpReqQqtForm)
async def get_mod_def_http_req_qqt(**kwargs):
    """获取HTTP请求过滤 请求头过滤"""
    api = DefHttpReqQqt()
    data = await api.get_mod_def_http_req_qqt(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="add_mod_def_http_req_qqt", form=mod_form.AddDefHttpReqQqtForm)
async def add_mod_def_http_req_qqt(**kwargs):
    """添加HTTP请求过滤 请求头过滤"""
    api = DefHttpReqQqt()
    data = await api.add_mod_def_http_req_qqt(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_http_req_qqt", form=mod_form.SetDefHttpReqQqtForm)
async def set_mod_def_http_req_qqt(**kwargs):
    """设置HTTP请求过滤 请求头过滤"""
    api = DefHttpReqQqt()
    data = await api.set_mod_def_http_req_qqt(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="del_mod_def_http_req_qqt", form=mod_form.DelDefHttpReqQqtForm)
async def del_mod_def_http_req_qqt(**kwargs):
    """删除HTTP请求过滤 请求头过滤"""
    api = DefHttpReqQqt()
    data = await api.del_mod_def_http_req_qqt(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_http_req_qqlx_cl")
async def get_mod_def_http_req_qqlx_cl(**kwargs):
    """获取HTTP请求过滤 请求类型常量"""
    api = DefHttpReqQqlx()
    data = await api.get_mod_def_http_req_qqlx_cl()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_http_req_qqlx", form=mod_form.DefHttpReqQqlxForm)
async def get_mod_def_http_req_qqlx(**kwargs):
    """获取HTTP请求过滤 请求类型"""
    api = DefHttpReqQqlx()
    data = await api.get_mod_def_http_req_qqlx(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="add_mod_def_http_req_qqlx", form=mod_form.AddDefHttpReqQqlxForm)
async def add_mod_def_http_req_qqlx(**kwargs):
    """添加HTTP请求过滤 请求类型"""
    api = DefHttpReqQqlx()
    data = await api.add_mod_def_http_req_qqlx(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_http_req_qqlx", form=mod_form.SetDefHttpReqQqlxForm)
async def set_mod_def_http_req_qqlx(**kwargs):
    """设置HTTP请求过滤 请求类型"""
    api = DefHttpReqQqlx()
    data = await api.set_mod_def_http_req_qqlx(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="del_mod_def_http_req_qqlx", form=mod_form.DelDefHttpReqQqlxForm)
async def del_mod_def_http_req_qqlx(**kwargs):
    """删除HTTP请求过滤 请求类型"""
    api = DefHttpReqQqlx()
    data = await api.del_mod_def_http_req_qqlx(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_gnw_fw", form=mod_form.DefGnwFwForm)
async def get_mod_def_gnw_fw(**kwargs):
    """获取禁止国内外访问"""
    api = DefGnwFw()
    data = await api.get_mod_def_gnw_fw(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_gnw_fw", form=mod_form.SetDefGnwFwForm)
async def set_mod_def_gnw_fw(**kwargs):
    """设置禁止国内外访问"""
    api = DefGnwFw()
    data = await api.set_mod_def_gnw_fw(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_conf_mod", form=mod_form.ConfModForm)
async def get_conf_mod(**kwargs):
    """获取配置"""
    api = ConfMod()
    data = await api.get_conf_mod(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_conf_mod_open", form=mod_form.ConfModOpenForm)
async def set_conf_mod_open(**kwargs):
    """修改设置开启/关闭"""
    api = ConfMod()
    data = await api.set_conf_mod_open(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_conf_mod", form=mod_form.SetConfModForm)
async def set_conf_mod(**kwargs):
    """修改设置"""
    api = ConfMod()
    data = await api.set_conf_mod(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="dc_conf_mod")
async def dc_conf_mod(**kwargs):
    """导出配置"""
    api = ConfMod()
    data = await api.dc_conf_mod()
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="dr_conf_mod", form=mod_form.DrConfModForm)
async def dr_conf_mod(**kwargs):
    """导入配置"""
    api = ConfMod()
    data = await api.dr_conf_mod(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_sql_inj", form=mod_form.DefSqlInjForm)
async def get_mod_def_sql_inj(**kwargs):
    """获取SQL注入防御"""
    api = DefSqlInj()
    data = await api.get_mod_def_sql_inj(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_sql_inj_open_rule", form=mod_form.DefSqlInjOpenForm)
async def set_mod_def_sql_inj_open_rule(**kwargs):
    """修改SQL注入防御开启/关闭"""
    api = DefSqlInj()
    data = await api.set_mod_def_sql_inj_open_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_xss", form=mod_form.DefXssForm)
async def get_mod_def_xss(**kwargs):
    """获取XSS注入防御"""
    api = DefXss()
    data = await api.get_mod_def_xss(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_xss_open_rule", form=mod_form.DefXssOpenForm)
async def set_mod_def_xss_open_rule(**kwargs):
    """修改XSS注入防御开启/关闭"""
    api = DefXss()
    data = await api.set_mod_def_xss_open_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_cookies", form=mod_form.DefCookiesForm)
async def get_mod_def_cookies(**kwargs):
    """获取Cookies防御"""
    api = DefCookies()
    data = await api.get_mod_def_cookies(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_cookies_open_rule", form=mod_form.DefCookiesOpenForm)
async def set_mod_def_cookies_open_rule(**kwargs):
    """修改Cookies防御开启/关闭"""
    api = DefCookies()
    data = await api.set_mod_def_cookies_open_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="add_mod_def_cookies", form=mod_form.AddDefCookiesForm)
async def add_mod_def_cookies(**kwargs):
    """添加Cookies防御"""
    api = DefCookies()
    data = await api.add_mod_def_cookies(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_cookies", form=mod_form.SetDefCookiesForm)
async def set_mod_def_cookies(**kwargs):
    """设置Cookies防御"""
    api = DefCookies()
    data = await api.set_mod_def_cookies(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="del_mod_def_cookies", form=mod_form.DelDefCookiesForm)
async def del_mod_def_cookies(**kwargs):
    """删除Cookies防御"""
    api = DefCookies()
    data = await api.del_mod_def_cookies(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_down", form=mod_form.DefDownForm)
async def get_mod_def_down(**kwargs):
    """恶意下载防御"""
    api = DefDown()
    data = await api.get_mod_def_down(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_down_open_rule", form=mod_form.DefDownOpenForm)
async def set_mod_def_down_open_rule(**kwargs):
    """修改恶意下载防御开启/关闭"""
    api = DefDown()
    data = await api.set_mod_def_down_open_rule(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_url_bh_jzzxphp", form=mod_form.DefUrlBhJzzxphpForm)
async def get_mod_def_url_bh_jzzxphp(**kwargs):
    """URL保护 禁止执行php"""
    api = DefUrlBh()
    data = await api.get_mod_def_url_bh_jzzxphp(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_url_bh_jzzxphp", form=mod_form.SetDefUrlBhJzzxphpForm)
async def set_mod_def_url_bh_jzzxphp(**kwargs):
    """URL保护 禁止执行php"""
    api = DefUrlBh()
    data = await api.set_mod_def_url_bh_jzzxphp(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_url_bh_zdcsfw", form=mod_form.DefUrlBhZdcsfwForm)
async def get_mod_def_url_bh_zdcsfw(**kwargs):
    """获取URL保护 指定参数访问"""
    api = DefUrlBh()
    data = await api.get_mod_def_url_bh_zdcsfw(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="add_mod_def_url_bh_zdcsfw", form=mod_form.AddDefUrlBhZdcsfwForm)
async def add_mod_def_url_bh_zdcsfw(**kwargs):
    """添加URL保护 指定参数访问"""
    api = DefUrlBh()
    data = await api.add_mod_def_url_bh_zdcsfw(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_url_bh_zdcsfw", form=mod_form.SetDefUrlBhZdcsfwForm)
async def set_mod_def_url_bh_zdcsfw(**kwargs):
    """设置URL保护 指定参数访问"""
    api = DefUrlBh()
    data = await api.set_mod_def_url_bh_zdcsfw(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="del_mod_def_url_bh_zdcsfw", form=mod_form.DelDefUrlBhZdcsfwForm)
async def del_mod_def_url_bh_zdcsfw(**kwargs):
    """删除URL保护 指定参数访问"""
    api = DefUrlBh()
    data = await api.del_mod_def_url_bh_zdcsfw(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_upload", form=mod_form.DefUploadForm)
async def get_mod_def_upload(**kwargs):
    """获取恶意文件上传防御"""
    api = DefUpload()
    data = await api.get_mod_def_upload(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_upload", form=mod_form.SetDefUploadForm)
async def set_mod_def_upload(**kwargs):
    """设置恶意文件上传防御"""
    api = DefUpload()
    data = await api.set_mod_def_upload(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_crawler", form=mod_form.DefCrawlerForm)
async def get_mod_def_crawler(**kwargs):
    """获取恶意爬虫防御"""
    api = DefCrawler()
    data = await api.get_mod_def_crawler(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_crawler", form=mod_form.SetDefCrawlerForm)
async def set_mod_def_crawler(**kwargs):
    """设置恶意爬虫防御"""
    api = DefCrawler()
    data = await api.set_mod_def_crawler(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_scan", form=mod_form.DefScanForm)
async def get_mod_def_scan(**kwargs):
    """获取恶意扫描器防御"""
    api = DefScan()
    data = await api.get_mod_def_scan(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_scan", form=mod_form.SetDefScanForm)
async def set_mod_def_scan(**kwargs):
    """设置恶意扫描器防御"""
    api = DefScan()
    data = await api.set_mod_def_scan(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_resp_xytm", form=mod_form.DefRespXytmForm)
async def get_mod_def_resp_xytm(**kwargs):
    """获取请求脱敏"""
    api = DefRespXytm()
    data = await api.get_mod_def_resp_xytm(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_resp_xytm", form=mod_form.SetDefRespXytmForm)
async def set_mod_def_resp_xytm(**kwargs):
    """设置请求脱敏"""
    api = DefRespXytm()
    data = await api.set_mod_def_resp_xytm(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_req_lj_wjc", form=mod_form.DefReqLjWjcForm)
async def get_mod_def_req_lj_wjc(**kwargs):
    """获取请求敏感词拦截 违禁词"""
    api = DefReqLj()
    data = await api.get_mod_def_req_lj_wjc(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_req_lj_wjc", form=mod_form.SetDefReqLjWjcForm)
async def set_mod_def_req_lj_wjc(**kwargs):
    """设置请求敏感词拦截 违禁词"""
    api = DefReqLj()
    data = await api.set_mod_def_req_lj_wjc(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="get_mod_def_req_lj_urlcsgl", form=mod_form.DefReqLjUrlcsglForm)
async def get_mod_def_req_lj_urlcsgl(**kwargs):
    """获取请求敏感词拦截 URL级参数过滤"""
    api = DefReqLj()
    data = await api.get_mod_def_req_lj_urlcsgl(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="add_mod_def_req_lj_urlcsgl", form=mod_form.AddDefReqLjUrlcsglForm)
async def add_mod_def_req_lj_urlcsgl(**kwargs):
    """添加请求敏感词拦截 URL级参数过滤"""
    api = DefReqLj()
    data = await api.add_mod_def_req_lj_urlcsgl(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="set_mod_def_req_lj_urlcsgl", form=mod_form.SetDefReqLjUrlcsglForm)
async def set_mod_def_req_lj_urlcsgl(**kwargs):
    """设置请求敏感词拦截 URL级参数过滤"""
    api = DefReqLj()
    data = await api.set_mod_def_req_lj_urlcsgl(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))


@app.route(name="del_mod_def_req_lj_urlcsgl", form=mod_form.DelDefReqLjUrlcsglForm)
async def del_mod_def_req_lj_urlcsgl(**kwargs):
    """删除请求敏感词拦截 URL级参数过滤"""
    api = DefReqLj()
    data = await api.del_mod_def_req_lj_urlcsgl(kwargs)
    return jsonify(data=data, msg=i18n.translate("STATUS_OK"))
