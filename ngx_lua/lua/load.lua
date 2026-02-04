-- 初始化
SAFEWAF_MODS                    = {}
SAFEWAF_RULES                   = {}
SAFEWAF_RUN_PATH                = "/www/server/safewaf/lua"
SAFEWAF_MODULE_PATH             = SAFEWAF_RUN_PATH .. "/plugin"
SAFEWAF_PUBLIC_PATH             = SAFEWAF_RUN_PATH .. "/utils"
SAFEWAF_INC                     = SAFEWAF_RUN_PATH .. "/ext"
SAFEWAF_RULE_PATH               = SAFEWAF_RUN_PATH .. "/exc/"
SAFEWAF_HTML                    = SAFEWAF_RUN_PATH .. "/html"
SAFEWAF_I18N                    = SAFEWAF_RUN_PATH .. "/i18n"
SAFEWAF_DB                      = SAFEWAF_RUN_PATH .. "/db"
SAFEWAF_SHELL                   = SAFEWAF_RUN_PATH .. "/shell"
-- 设置环境变量
package.path                    = SAFEWAF_MODULE_PATH .. "/?.lua;" .. SAFEWAF_PUBLIC_PATH .. "/?.lua"
package.cpath                   = SAFEWAF_INC .. "/?.so;" .. package.cpath
Json                            = require "cjson"
Helpers                         = require "helpers"
Dbs                             = require "dbs"
Webhook                         = require "webhook"
IpInfo                          = require "ipinfo"
Route                           = require "route"
IpTools                         = require "iptools"
IpDb                            = require "ipdb"
DB                              = nil
DbCount                         = nil
-- 读取配置
Config                          = Json.decode(Helpers.read_file_body(SAFEWAF_RUN_PATH .. '/config.json'))
Site_config                     = Json.decode(Helpers.read_file_body(SAFEWAF_RUN_PATH .. '/site.json'))
Lang                            = Config['lang'] or "zh-CN"
-- 读取响应页面
SAFEWAF_RULES.get_html          = Helpers.read_file_body(SAFEWAF_HTML .. '/' .. Lang .. '/' .. 'get.html')
SAFEWAF_RULES.ip_html           = Helpers.read_file_body(SAFEWAF_HTML .. '/' .. Lang .. '/' .. 'ip.html')
SAFEWAF_RULES.city_html         = Helpers.read_file_body(SAFEWAF_HTML .. '/' .. Lang .. '/' .. 'city.html')
SAFEWAF_RULES.error_404         = Helpers.read_file_body(SAFEWAF_HTML .. '/' .. Lang .. '/' .. '404.html')
SAFEWAF_RULES.limit_html        = Helpers.read_file_body(SAFEWAF_HTML .. '/' .. Lang .. '/' .. 'limit.html')
SAFEWAF_RULES.limit_json        = Json.decode(Helpers.read_file_body(SAFEWAF_HTML .. '/' .. Lang .. '/' .. 'limit.json'))
I18N                            = Json.decode(Helpers.read_file_body(SAFEWAF_I18N .. '/' .. Lang .. '.json'))
GJLX                            = Helpers.read_file('gjlx')    -- 攻击类型
AckWebHook                      = Helpers.read_file('webhook') -- wenhook
-- 黑白名单
SAFEWAF_RULES.ip_black_rules    = Helpers.read_file('ip_black')
SAFEWAF_RULES.ip_white_rules    = Helpers.read_file('ip_white')
SAFEWAF_RULES.ip_white_v6       = Helpers.read_file('ip_white_v6')
SAFEWAF_RULES.ip_black_v6       = Helpers.read_file('ip_black_v6')
SAFEWAF_RULES.url_white_rules   = Helpers.read_file('url_white')
SAFEWAF_RULES.url_black_rules   = Helpers.read_file('url_black')
SAFEWAF_RULES.ua_white_rules    = Helpers.read_file('ua_white')
SAFEWAF_RULES.ua_black_rules    = Helpers.read_file('ua_black')
SAFEWAF_RULES.reg_tions_rules   = Helpers.read_file('reg_tions')
SAFEWAF_RULES.reg_city_rules    = Helpers.read_file('reg_city')
SAFEWAF_RULES.renji_black_rules = Helpers.read_file('renji_black')
SAFEWAF_RULES.renji_white_rules = Helpers.read_file('renji_white')
SAFEWAF_RULES.reg_en            = Helpers.read_file('reg_en')
-- 自定义规则
SAFEWAF_RULES.waf_llxz          = Helpers.read_file('waf_llxz')
SAFEWAF_RULES.waf_nday          = Helpers.read_file('waf_nday')
SAFEWAF_RULES.waf_diy_rule      = Helpers.read_file('waf_diy_rule')
-- 验证码图片
SAFEWAF_RULES.captcha_num2      = Json.decode(Helpers.read_file_body(SAFEWAF_INC .. '/captcha/num2.json'))

-- 加载插件
Helpers.load_modules()

--加载蜘蛛IP进入到内存中
local load_spider               = {}
load_spider                     = IpInfo.load_spider()
SAFEWAF_RULES.load_spider_count = Helpers.arrlen(load_spider)
SAFEWAF_RULES.load_spider       = IpTools.new(load_spider)

--设置IPV6白名单
local ipv6_w                    = {}
SAFEWAF_RULES.ipv6_white_count  = 0
for _, v in ipairs(SAFEWAF_RULES.ip_white_v6) do
    --判断长度是否大于6
    SAFEWAF_RULES.ipv6_white_count = SAFEWAF_RULES.ipv6_white_count + 1
    table.insert(ipv6_w, v[1])
end
SAFEWAF_RULES.ipv6_white = IpTools.new(ipv6_w)
--设置IPV6黑名单
local ipv6_b = {}
SAFEWAF_RULES.ipv6_black_count = 0
for _, v in ipairs(SAFEWAF_RULES.ip_black_v6) do
    --判断长度是否大于6
    SAFEWAF_RULES.ipv6_black_count = SAFEWAF_RULES.ipv6_black_count + 1
    table.insert(ipv6_b, v[1])
end
SAFEWAF_RULES.ipv6_black = IpTools.new(ipv6_b)
