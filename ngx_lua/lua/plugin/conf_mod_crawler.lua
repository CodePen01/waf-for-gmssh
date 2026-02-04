-- 防自动化与爬虫
local conf_mod_crawler = {}
local ngx_match = ngx.re.find

-- 恶意爬虫防御
function conf_mod_crawler.def_crawler()
    local mod_name = 'def_crawler'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local xyym = mod_conf['xyym']
    local rdata = mod_conf['conf']['list']

    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri

    for _, v in ipairs(rdata) do
        if ngx.ctx.ua == v then
            Helpers.logs('恶意爬虫防御 ' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_CRAWLER'], I18N['CONF_MOD_DEF_CRAWLER'], I18N['CONF_MOD_DEF_CRAWLER_MSG'], '')
            Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
            return true
        end
        if ngx.re.match(ngx.ctx.ua, v, 'ijo') then
            Helpers.logs('恶意爬虫防御 ' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_CRAWLER'], I18N['CONF_MOD_DEF_CRAWLER'], I18N['CONF_MOD_DEF_CRAWLER_MSG'], '')
            Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
            return true
        end

        ::continue::
    end

    return false
end

-- 恶意扫描器防御
function conf_mod_crawler.def_scan()
    local mod_name = 'def_scan'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local xyym = mod_conf['xyym']
    local rdata = mod_conf['conf']['sz']

    local header = rdata['header']
    local cookie = rdata['cookie']
    local args = rdata['args']

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri

    if Helpers.arrlen(header) > 0 then
        local header_data = ""
        if ngx.ctx.request_header then
            for key, valu in pairs(ngx.ctx.request_header) do
                if type(valu) == "string" then
                    header_data = header_data .. key .. ": " .. valu .. "\n"
                end
                if type(valu) == "table" then
                    for key2, val2 in pairs(valu) do
                        header_data = header_data .. key .. ": " .. val2 .. "\n"
                    end
                end
            end
        end
        -- 规则匹配
        for _, v in ipairs(header) do
            if ngx.re.match(header_data, v, 'ijo') then
                Helpers.logs('恶意扫描器防御 header ' .. uri .. ' IP：' .. ip)
                Dbs.xlog(GJLX['CONF_MOD_DEF_SCAN'], I18N['CONF_MOD_DEF_SCAN'], I18N['CONF_MOD_DEF_SCAN_HEADER_MSG'], '')
                Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
                return true
            end

            ::continue::
        end
    end

    if Helpers.arrlen(cookie) > 0 then
        local headers = ngx.req.get_headers()
        if headers ~= nil and headers['Cookie'] then
            for _, v in ipairs(cookie) do
                if ngx.re.match(headers['Cookie'], v, 'ijo') then
                    Helpers.logs('恶意扫描器防御 cookie ' .. uri .. ' IP：' .. ip)
                    Dbs.xlog(GJLX['CONF_MOD_DEF_SCAN'], I18N['CONF_MOD_DEF_SCAN'], I18N['CONF_MOD_DEF_SCAN_COOKIE_MSG'], '')
                    Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
                    return true
                end

                ::continue::
            end
        end
    end
    if Helpers.arrlen(args) > 0 then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        local get_args = ngx.var.args
        for _, v in ipairs(args) do
            if get_args ~= nil and #get_args > 0 then
                if ngx.re.match(get_args, v, 'ijo') then
                    Helpers.logs('恶意扫描器防御 args ' .. uri .. ' IP：' .. ip)
                    Dbs.xlog(GJLX['CONF_MOD_DEF_SCAN'], I18N['CONF_MOD_DEF_SCAN'], I18N['CONF_MOD_DEF_SCAN_ARGS_MSG'], '')
                    Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
                    return true
                end
            end
            if body ~= nil and #body > 0 then
                if ngx.re.match(body, v, 'ijo') then
                    Helpers.logs('恶意扫描器防御 args ' .. uri .. ' IP：' .. ip)
                    Dbs.xlog(GJLX['CONF_MOD_DEF_SCAN'], I18N['CONF_MOD_DEF_SCAN'], I18N['CONF_MOD_DEF_SCAN_ARGS_MSG'], '')
                    Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
                    return true
                end
            end

            ::continue::
        end
    end




    return false
end

return conf_mod_crawler
