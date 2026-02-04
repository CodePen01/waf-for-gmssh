-- 防注入攻击
local conf_mod_sql_def = {}
local ngx_match = ngx.re.find

-- SQL注入防御
function conf_mod_sql_def.def_sql_inj()
    local mod_name = 'def_sql_inj'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local xyym = mod_conf['xyym']
    local rdata = mod_conf['conf']['list']

    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local request_uri = ngx.var.request_uri
    for _, v in ipairs(rdata) do
        if not v.open then goto continue end
        if request_uri ~= nil and ngx_match(request_uri, v.rule, 'ijo') then
            Helpers.logs('SQL注入防御：' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_SQL_INJ'], I18N['CONF_MOD_DEF_SQL_INJ'], I18N['CONF_MOD_DEF_SQL_INJ_MSG'], '')
            Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
            return true
        end
        if body ~= nil and ngx_match(body, v.rule, 'ijo') then
            Helpers.logs('SQL注入防御：' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_SQL_INJ'], I18N['CONF_MOD_DEF_SQL_INJ'], I18N['CONF_MOD_DEF_SQL_INJ_MSG'], '')
            Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
            return true
        end

        ::continue::
    end

    return false
end

-- 命令执行拦截
function conf_mod_sql_def.def_rce()
    local mod_name = 'def_rce'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local xyym = mod_conf['xyym']
    local rdata = mod_conf['conf']['list']

    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local request_uri = ngx.var.request_uri
    for _, v in ipairs(rdata) do
        if not v.open then goto continue end
        if request_uri ~= nil and ngx_match(request_uri, v.rule, 'ijo') then
            Helpers.logs('命令执行拦截：' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_RCE'], I18N['CONF_MOD_DEF_RCE'], I18N['CONF_MOD_DEF_RCE_MSG'], '')
            Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
            return true
        end
        if body ~= nil and ngx_match(body, v.rule, 'ijo') then
            Helpers.logs('命令执行拦截：' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_RCE'], I18N['CONF_MOD_DEF_RCE'], I18N['CONF_MOD_DEF_RCE_MSG'], '')
            Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
            return true
        end

        ::continue::
    end

    return false
end

-- XSS防御
function conf_mod_sql_def.def_xss()
    local mod_name = 'def_xss'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local xyym = mod_conf['xyym']
    local rdata = mod_conf['conf']['list']

    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local request_uri = ngx.var.request_uri
    for _, v in ipairs(rdata) do
        if not v.open then goto continue end
        if request_uri ~= nil and ngx_match(request_uri, v.rule, 'ijo') then
            Helpers.logs('XSS防御：' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_XSS'], I18N['CONF_MOD_DEF_XSS'], I18N['CONF_MOD_DEF_XSS_MSG'], '')
            Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
            return true
        end
        if body ~= nil and ngx_match(body, v.rule, 'ijo') then
            Helpers.logs('XSS防御：' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_XSS'], I18N['CONF_MOD_DEF_XSS'], I18N['CONF_MOD_DEF_XSS_MSG'], '')
            Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
            return true
        end

        ::continue::
    end

    return false
end

-- 恶意Cookie防御
function conf_mod_sql_def.def_cookies()
    local mod_name = 'def_cookies'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local xyym = mod_conf['xyym']
    local rdata = mod_conf['conf']['list']

    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    local headers = ngx.req.get_headers()
    for _, v in ipairs(rdata) do
        if not v.open then goto continue end
        if headers ~= nil and headers['Cookie'] and ngx_match(headers['Cookie'], v.rule, 'ijo') then
            Helpers.logs('恶意Cookie防御：' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_COOKIES'], I18N['CONF_MOD_DEF_COOKIES'], I18N['CONF_MOD_DEF_COOKIES_MSG'], '')
            Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
            return true
        end

        ::continue::
    end

    return false
end

return conf_mod_sql_def
