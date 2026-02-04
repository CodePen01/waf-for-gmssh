local traffic_guard = {}

-- IP黑名单匹配
function traffic_guard.ip_black()
    local ip = ngx.ctx.ip
    if ngx.ctx.ipv6 == 1 and SAFEWAF_RULES.ipv6_black_count >= 1 then
        if SAFEWAF_RULES.ipv6_black:match(ngx.ctx.ip) then
            Helpers.logs('IPV6黑名单拦截：' .. ip)
            Dbs.xlog(GJLX['IP_BLACK'], I18N['IP_BLACK'], I18N['IP_BLACK_MSG'], '')
            Helpers.return_html(403, SAFEWAF_RULES.ip_html)
        end
        return false
    else
        if Helpers.arrlen(SAFEWAF_RULES.ip_black_rules) == 0 then return false end
        for _, rule in ipairs(SAFEWAF_RULES.ip_black_rules)
        do
            if IpInfo.compare_ip2(rule) then
                Helpers.logs('IP黑名单拦截：' .. ip)
                Dbs.xlog(GJLX['IP_BLACK'], I18N['IP_BLACK'], I18N['IP_BLACK_MSG'], '')
                Helpers.return_html(403, SAFEWAF_RULES.ip_html)
                return true
            end
        end
        return false
    end
end

-- IP白名单匹配
function traffic_guard.ip_white()
    local ip = ngx.ctx.ip
    if ngx.ctx.ipv6 == 1 and SAFEWAF_RULES.ipv6_white_count >= 1 then
        if SAFEWAF_RULES.ipv6_white:match(ip) then
            Helpers.logs('IPV6白名单：' .. ip)
            return true
        end
        return false
    else
        if Helpers.count_size(SAFEWAF_RULES.ip_white_rules) == 0 then return false end
        if ip == '127.0.0.1' then return false end
        for _, rule in ipairs(SAFEWAF_RULES.ip_white_rules) do
            if IpInfo.compare_ip2(rule) then
                Helpers.logs('IP白名单：' .. ip)
                return true
            end
        end
        return false
    end
end

-- URL白名单匹配
function traffic_guard.url_white()
    local ip = ngx.ctx.ip
    if Helpers.arrlen(SAFEWAF_RULES.url_white_rules) == 0 then return false end
    for __, v in pairs(SAFEWAF_RULES.url_white_rules)
    do
        if ngx.ctx.request_uri == v then
            Helpers.logs('URL白名单：' .. ngx.ctx.request_uri .. ' IP：' .. ip)
            return true
        end
        if ngx.re.match(ngx.ctx.request_uri, v, 'ijo') then
            Helpers.logs('URL白名单：' .. ngx.ctx.request_uri .. ' IP：' .. ip)
            return true
        end
    end
    return false
end

-- URI黑名单匹配
function traffic_guard.url_black()
    local ip = ngx.ctx.ip
    if Helpers.arrlen(SAFEWAF_RULES.url_black_rules) == 0 then return false end
    for __, v in pairs(SAFEWAF_RULES.url_black_rules)
    do
        if ngx.ctx.request_uri == v then
            Helpers.logs('URL黑名单拦截：' .. ngx.ctx.request_uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['URL_BLACK'], I18N['URL_BLACK'], I18N['URL_BLACK_MSG'], '')
            Helpers.return_html(403, SAFEWAF_RULES.get_html)
            return true
        end
        if ngx.re.match(ngx.ctx.request_uri, v, 'ijo') then
            Helpers.logs('URL黑名单拦截：' .. ngx.ctx.request_uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['URL_BLACK'], I18N['URL_BLACK'], I18N['URL_BLACK_MSG'], '')
            Helpers.return_html(403, SAFEWAF_RULES.get_html)
            return true
        end
    end
    return false
end

-- UA白名单匹配
function traffic_guard.ua_white()
    local ip = ngx.ctx.ip
    if ngx.ctx.ua == "_" then return false end
    if type(ngx.ctx.ua) ~= 'string' then ngx.exit(200) end
    if Helpers.arrlen(SAFEWAF_RULES.ua_white_rules) == 0 then return false end

    for __, v in pairs(SAFEWAF_RULES.ua_white_rules)
    do
        if ngx.ctx.ua == v then
            Helpers.logs('UA白名单：' .. ngx.ctx.ua .. ' IP：' .. ip)
            return true
        end
        if ngx.re.match(ngx.ctx.ua, v, 'ijo') then
            Helpers.logs('UA白名单：' .. ngx.ctx.ua .. ' IP：' .. ip)
            return true
        end
    end
    return false
end

-- UA黑名单匹配
function traffic_guard.ua_black()
    local ip = ngx.ctx.ip
    if ngx.ctx.ua == "_" then return false end
    if type(ngx.ctx.ua) ~= 'string' then ngx.exit(200) end
    if Helpers.count_size(SAFEWAF_RULES.ua_black_rules) == 0 then return false end
    for __, v in pairs(SAFEWAF_RULES.ua_black_rules)
    do
        if ngx.ctx.ua == v then
            Helpers.logs('UA黑名单拦截：' .. ngx.ctx.ua .. ' IP：' .. ip)
            Dbs.xlog(GJLX['UA_BLACK'], I18N['UA_BLACK'], I18N['UA_BLACK_MSG'], '')
            Helpers.return_html(403, SAFEWAF_RULES.get_html)
            return true
        end
        if ngx.re.match(ngx.ctx.ua, v, 'ijo') then
            Helpers.logs('UA黑名单拦截：' .. ngx.ctx.ua .. ' IP：' .. ip)
            Dbs.xlog(GJLX['UA_BLACK'], I18N['UA_BLACK'], I18N['UA_BLACK_MSG'], '')
            Helpers.return_html(403, SAFEWAF_RULES.get_html)
            return true
        end
    end
    return false
end

-- 人机黑名单匹配
function traffic_guard.renji_black()
    local ip = ngx.ctx.ip
    if Helpers.arrlen(SAFEWAF_RULES.renji_black_rules) == 0 then return false end
    for __, v in pairs(SAFEWAF_RULES.renji_black_rules)
    do
        if ngx.ctx.request_uri == v then
            Helpers.logs('人机黑名单拦截：' .. ngx.ctx.request_uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['RENJI_BLACK'], I18N['RENJI_BLACK'], I18N['RENJI_BLACK_MSG'], '')
            SAFEWAF_MODS.cc.renjiyanzheng('code')
            return true
        end
        if ngx.re.match(ngx.ctx.request_uri, v, 'ijo') then
            Helpers.logs('人机黑名单拦截：' .. ngx.ctx.request_uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['RENJI_BLACK'], I18N['RENJI_BLACK'], I18N['RENJI_BLACK_MSG'], '')
            SAFEWAF_MODS.cc.renjiyanzheng('code')
            return true
        end
    end
    return false
end

-- URL白名单匹配
function traffic_guard.renji_white()
    local ip = ngx.ctx.ip
    if Helpers.arrlen(SAFEWAF_RULES.renji_white_rules) == 0 then return false end
    for __, v in pairs(SAFEWAF_RULES.renji_white_rules)
    do
        if ngx.ctx.request_uri == v then
            Helpers.logs('人机白名单：' .. ngx.ctx.request_uri .. ' IP：' .. ip)
            return true
        end
        if ngx.re.match(ngx.ctx.request_uri, v, 'ijo') then
            Helpers.logs('人机白名单：' .. ngx.ctx.request_uri .. ' IP：' .. ip)
            return true
        end
    end
    return false
end

return traffic_guard
