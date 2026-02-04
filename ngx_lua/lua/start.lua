-- waf 过滤
local worker_pid = ngx.worker.pid()
if not ngx.shared.safewaf:get("works" .. worker_pid) then
    ngx.shared.safewaf:set("works" .. worker_pid, 1)
end

local function init_ngx_ctx()
    ngx.ctx.ip          = ""
    ngx.ctx.country     = "" -- 国家
    ngx.ctx.ip_province = "" -- 省
    ngx.ctx.ip_city     = "" -- 市
    ngx.ctx.ip_area     = "" -- 区
    ngx.ctx.ip_isp      = "" -- 运营商
    ngx.ctx.ip_dazhou   = "" -- 大洲
    ngx.ctx.ip_en       = "" -- 英文国家名称
    ngx.ctx.ip_lng      = "" -- 经度
    ngx.ctx.ip_lat      = "" -- 纬度
    ngx.ctx.today       = ngx.today()
    ngx.ctx.local_time  = ngx.localtime()
    ngx.ctx.server_name = Helpers.get_server_name()
    ngx.ctx.ua          = ""
    ngx.ctx.referer     = ""
    ngx.ctx.xlog_flag   = false
    if not Config['open'] then return false end
    if not Helpers.is_site_config('open') then return false end
    ngx.ctx.uri = ngx.var.uri
    ngx.ctx.url_split = Helpers.get_request_uri()
    ngx.ctx.request_uri = ngx.var.request_uri
    ngx.ctx.method = ngx.req.get_method()
    -- --获取请求头信息
    ngx.ctx.request_header = ngx.req.get_headers(20000)
    ngx.ctx.url_token = ngx.md5(ngx.ctx.server_name .. ngx.ctx.url_split)
    if ngx.var.http_user_agent and ngx.var.http_user_agent ~= "" then
        ngx.ctx.ua = ngx.var.http_user_agent
    end
    ngx.ctx.ua_md5 = ngx.md5(ngx.ctx.ua)
    if ngx.var.http_referer and ngx.var.http_referer ~= "" then
        ngx.ctx.referer = ngx.var.http_referer
    end
    -- --获取客户端的IP
    IpInfo.get_ip_info()
    if ngx.ctx.ip == '127.0.0.1' then return false end

    -- --获取args参数
    ngx.ctx.get_uri_args = ngx.req.get_uri_args(100000)
end

local function start_waf_rule()
    -- 日志输出
    -- SAFEWAF_MODS.test.show_log()
    -- SAFEWAF_MODS.test.debug()

    -- 404检测
    SAFEWAF_MODS.http_check.check_404()

    -- IP检测
    if IpInfo.ip_check() then return true end

    -- 防护规则 黑白名单
    if SAFEWAF_MODS.traffic_guard.ip_white() then return true end
    SAFEWAF_MODS.traffic_guard.ip_black()
    if SAFEWAF_MODS.traffic_guard.ua_white() then return true end
    if SAFEWAF_MODS.traffic_guard.url_white() then return true end
    SAFEWAF_MODS.traffic_guard.ua_black()
    SAFEWAF_MODS.traffic_guard.url_black()
    SAFEWAF_MODS.traffic_guard.renji_black()

    Route.cc() -- 人机验证

    -- 地区检测
    SAFEWAF_MODS.city.parse_regions()
    SAFEWAF_MODS.city.parse_city()

    SAFEWAF_MODS.hw_mode.check()       -- 护网模式检测
    SAFEWAF_MODS.fhgz_nday.check()     -- 防护规则 专属规则
    SAFEWAF_MODS.fhgz_llxz.check()     -- 防护规则 流量限制
    SAFEWAF_MODS.fhgz_diy_rule.check() -- 防护规则 自定义规则

    -- 全局配置 - 防CC防御
    SAFEWAF_MODS.conf_mod_cc_def.def_url_cc()           -- URL级CC防御
    SAFEWAF_MODS.conf_mod_cc_def.def_url_rjyz()         -- URL级人机验证
    SAFEWAF_MODS.conf_mod_cc_def.def_api_cc()           -- API CC防御
    SAFEWAF_MODS.conf_mod_cc_def.def_static_res()       -- 静态文件防护
    SAFEWAF_MODS.conf_mod_cc_def.def_dir_scan()         -- 目录扫描防御
    -- 全局配置 - 请求合规防御
    SAFEWAF_MODS.conf_mod_req_hg.def_robot()            -- 机器人防护
    SAFEWAF_MODS.conf_mod_req_hg.def_http_req_qqlx()    -- HTTP请求过滤 请求类型过滤
    SAFEWAF_MODS.conf_mod_req_hg.def_http_req_qqt()     -- HTTP请求过滤 请求头过滤
    SAFEWAF_MODS.conf_mod_req_hg.def_http_req_qqsl()    -- HTTP请求过滤 请求数量过滤
    SAFEWAF_MODS.conf_mod_req_hg.def_gnw_fw()           -- 禁止国内外访问
    -- 全局配置 - 防注入攻击
    SAFEWAF_MODS.conf_mod_sql_def.def_sql_inj()         -- SQL注入防御
    SAFEWAF_MODS.conf_mod_sql_def.def_rce()             -- 命令执行防御
    SAFEWAF_MODS.conf_mod_sql_def.def_xss()             -- XSS防御
    SAFEWAF_MODS.conf_mod_sql_def.def_cookies()         -- 恶意Cookie防御
    -- 全局配置 - 防资源滥用
    SAFEWAF_MODS.conf_mod_res_ly.def_down()             -- 恶意下载防御
    SAFEWAF_MODS.conf_mod_res_ly.def_url_bh_zdcsfw()    -- URL保护防御 指定参数访问的URL
    SAFEWAF_MODS.conf_mod_res_ly.def_url_bh_jzzxphp()   -- URL保护防御 禁止执行PHP的URL
    SAFEWAF_MODS.conf_mod_res_ly.def_upload()           -- 恶意文件上传防御
    -- 全局配置 - 防自动化与爬虫
    SAFEWAF_MODS.conf_mod_crawler.def_crawler()         -- 恶意爬虫防御
    SAFEWAF_MODS.conf_mod_crawler.def_scan()            -- 恶意扫描器防御
    -- 全局配置 - 敏感词
    SAFEWAF_MODS.conf_mod_mgc_word.def_req_lj_urlcsgl() -- 请求敏感词拦截 URL级参数过滤
    SAFEWAF_MODS.conf_mod_mgc_word.def_req_lj_wjc()     -- 请求敏感词拦截 违禁词


    -- WAF END
end


local function start()
    if not init_ngx_ctx() then return false end
    start_waf_rule()
end


local ok, error = pcall(function()
    return start()
end)

if not ok then
    if not ngx.shared.safewaf:get("safewaf_access") then
        Helpers.logs(error)
        ngx.shared.safewaf:set("safewaf_access", 1, 300)
    end
end
