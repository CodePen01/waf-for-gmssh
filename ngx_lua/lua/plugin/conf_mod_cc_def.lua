-- 防CC攻击
local conf_mod_cc_def = {}
local ngx_match = ngx.re.find


-- URL级CC防御
function conf_mod_cc_def.def_url_cc()
    local mod_name = 'def_url_cc'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local rdata = mod_conf['conf']['list']

    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    for _, v in ipairs(rdata) do
        -- 检查URL匹配
        local is_match_url = false
        if v.pp_mode == 1 then
            -- 完全匹配
            is_match_url = (uri == v.url)
        elseif v.pp_mode == 2 then
            -- 正则匹配
            is_match_url = ngx_match(uri, v.url, 'jo') ~= nil
        end
        if not is_match_url then goto continue end

        -- 生成token
        local token
        if v.tjwd_ip == 1 then
            -- 统计维度 1: ip+url
            token = ngx.md5(mod_name .. ip .. uri)
        else
            -- 统计维度 0: url
            token = ngx.md5(mod_name .. uri)
        end

        -- 初始化token值
        local exists = ngx.shared.safewaf:get(token)
        if not exists then
            ngx.shared.safewaf:set(token, 0, v.fwsj)
        end

        -- 增加计数并获取当前值
        local count, err = ngx.shared.safewaf:incr(token, 1)
        if not count then
            -- 如果incr失败，重新设置并获取
            ngx.shared.safewaf:set(token, 1, v.fwsj)
            count = 1
        end

        -- 检查是否超过阈值
        if count > v.fwcs then
            -- 执行响应动作
            Helpers.logs('URL级CC防御：' .. ' URL：' .. uri .. ' IP：' .. ip .. ' 计数：' .. count)

            if v.fslx == 1 then
                -- 封锁ip
                Dbs.xlog_time(GJLX['CONF_MOD_DEF_URL_CC'], I18N['CONF_MOD_DEF_URL_CC'], I18N['CONF_MOD_DEF_URL_CC_MSG'], '', v.fssj)
                IpInfo.ipblack_add(ip, v.fssj)
            else
                Dbs.xlog(GJLX['CONF_MOD_DEF_URL_CC'], I18N['CONF_MOD_DEF_URL_CC'], I18N['CONF_MOD_DEF_URL_CC_MSG'], '')
            end

            if v.xyym == 1 then
                -- 封锁ip
                ngx.exit(444)
            elseif v.xyym == 2 then
                -- 关闭链接
                ngx.exit(444)
            elseif Helpers.in_list(v.xyym, { 404, 403, 502, 503 }) then
                -- 返回状态码
                if v.fhgs == 1 then
                    -- 返回json
                    Helpers.return_message(v.xyym, SAFEWAF_RULES.limit_json)
                else
                    -- 返回html
                    Helpers.return_html(v.xyym, SAFEWAF_RULES.limit_html)
                end
            end
            return true
        end

        ::continue::
    end

    return false
end

-- URL人机验证
function conf_mod_cc_def.def_url_rjyz()
    local mod_name = 'def_url_rjyz'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local rdata = mod_conf['conf']['list']

    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    for _, v in ipairs(rdata) do
        -- 检查URL匹配
        local is_match_url = false
        if v.pp_mode == 1 then
            -- 完全匹配
            is_match_url = (uri == v.url)
        elseif v.pp_mode == 2 then
            -- 正则匹配
            is_match_url = ngx_match(uri, v.url, 'jo') ~= nil
        end
        if not is_match_url then goto continue end

        -- 判断v.csz不为空数组,循环v.csv
        if Helpers.arrlen(v.csz) > 0 then
            ngx.req.read_body()
            local body = ngx.req.get_body_data()
            local args = ngx.var.args
            for _, csz in ipairs(v.csz) do
                -- 匹配urlget和post参数
                if args ~= nil and csz ~= '' then
                    local is_match_get = ngx_match(args, csz, 'jo') ~= nil
                    if is_match_get then
                        Helpers.logs('URL人机验证，匹配参数：' .. csz .. ' URL：' .. uri .. ' IP：' .. ip)
                        Dbs.xlog(GJLX['CONF_MOD_DEF_URL_RJYZ'], I18N['CONF_MOD_DEF_URL_RJYZ'], I18N['CONF_MOD_DEF_URL_RJYZ_MSG'], '')
                        if v.yzfs == 1 then
                            SAFEWAF_MODS.cc.renjiyanzheng('tiao')
                        else
                            SAFEWAF_MODS.cc.renjiyanzheng('code')
                        end
                    end
                end
                if body ~= nil and csz ~= '' then
                    local is_match_post = ngx_match(body, csz, 'jo') ~= nil
                    if is_match_post then
                        Helpers.logs('URL人机验证，匹配参数：' .. csz .. ' URL：' .. uri .. ' IP：' .. ip)
                        Dbs.xlog(GJLX['CONF_MOD_DEF_URL_RJYZ'], I18N['CONF_MOD_DEF_URL_RJYZ'], I18N['CONF_MOD_DEF_URL_RJYZ_MSG'], '')
                        if v.yzfs == 1 then
                            SAFEWAF_MODS.cc.renjiyanzheng('tiao')
                        else
                            SAFEWAF_MODS.cc.renjiyanzheng('code')
                        end
                    end
                end
            end
        else
            -- 执行响应动作
            Helpers.logs('URL人机验证' .. ' URL：' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_URL_RJYZ'], I18N['CONF_MOD_DEF_URL_RJYZ'], I18N['CONF_MOD_DEF_URL_RJYZ_MSG'], '')
            if v.yzfs == 1 then
                SAFEWAF_MODS.cc.renjiyanzheng('tiao')
            else
                SAFEWAF_MODS.cc.renjiyanzheng('code')
            end
        end

        ::continue::
    end

    return false
end

-- API CC防御
function conf_mod_cc_def.def_api_cc()
    local mod_name = 'def_api_cc'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local rdata = mod_conf['conf']['list']
    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    for _, v in ipairs(rdata) do
        -- 检查URL匹配
        local is_match_url = false
        if v.pp_mode == 1 then
            -- 完全匹配
            is_match_url = (uri == v.url)
        elseif v.pp_mode == 2 then
            -- 正则匹配
            is_match_url = ngx_match(uri, v.url, 'jo') ~= nil
        end
        if not is_match_url then goto continue end

        -- 生成token
        local token
        if v.tjwd_ip == 1 then
            -- 统计维度 1: ip+url
            token = ngx.md5(mod_name .. ip .. uri)
        else
            -- 统计维度 0: url
            token = ngx.md5(mod_name .. uri)
        end

        -- 初始化token值
        local exists = ngx.shared.safewaf:get(token)
        if not exists then
            ngx.shared.safewaf:set(token, 0, v.fwsj)
        end

        -- 增加计数并获取当前值
        local count, err = ngx.shared.safewaf:incr(token, 1)
        if not count then
            -- 如果incr失败，重新设置并获取
            ngx.shared.safewaf:set(token, 1, v.fwsj)
            count = 1
        end
        -- 检查是否超过阈值
        if count > v.fwcs then
            -- 执行响应动作
            Helpers.logs('API CC防御：' .. ' URL：' .. uri .. ' IP：' .. ip .. ' 计数：' .. count)

            if v.fslx == 1 then
                -- 封锁ip
                Dbs.xlog_time(GJLX['CONF_MOD_DEF_API_CC'], I18N['CONF_MOD_DEF_API_CC'], I18N['CONF_MOD_DEF_API_CC_MSG'], '', v.fssj)
                IpInfo.ipblack_add(ip, v.fssj)
                Helpers.return_message(503, SAFEWAF_RULES.limit_json)
            else
                Dbs.xlog_time(GJLX['CONF_MOD_DEF_API_CC'], I18N['CONF_MOD_DEF_API_CC'], I18N['CONF_MOD_DEF_API_CC_MSG'], '', v.fssj)
                IpInfo.ipblack_add(ip, v.fssj)
                Helpers.return_message(503, SAFEWAF_RULES.limit_json)
            end

            return true
        end

        ::continue::
    end

    return false
end

-- 静态文件防护
function conf_mod_cc_def.def_static_res()
    local mod_name = 'def_static_res'
    local fwsj = 60
    local fwcs = 100

    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri

    -- 检查URL匹配
    if not Helpers.check_static() then return false end

    -- 生成token
    local token = ngx.md5(mod_name .. ip)

    -- 初始化token值
    local exists = ngx.shared.safewaf:get(token)
    if not exists then
        ngx.shared.safewaf:set(token, 0, fwsj)
    end

    -- 增加计数并获取当前值
    local count, err = ngx.shared.safewaf:incr(token, 1)
    if not count then
        -- 如果incr失败，重新设置并获取
        ngx.shared.safewaf:set(token, 1, fwsj)
        count = 1
    end
    -- 检查是否超过阈值
    if count > fwcs then
        -- 执行响应动作
        Helpers.logs('静态文件防护：' .. ' URL：' .. uri .. ' IP：' .. ip .. ' 计数：' .. count)

        Dbs.xlog_time(GJLX['CONF_MOD_DEF_STATIC_RES'], I18N['CONF_MOD_DEF_STATIC_RES'], I18N['CONF_MOD_DEF_STATIC_RES_MSG'], '', 300)
        IpInfo.ipblack_add(ip, 300)
        Helpers.return_html(503, SAFEWAF_RULES.limit_html)

        return true
    end

    return false
end

-- 目录扫描防御
function conf_mod_cc_def.def_dir_scan()
    local mod_name = 'def_dir_scan'

    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local fwsj = mod_conf['conf']['sz']['fwsj']
    local fwcs = mod_conf['conf']['sz']['fwcs']

    if fwsj <= 0 or fwcs <= 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri

    -- 生成token
    local token = ngx.md5(mod_name .. ip)

    -- 初始化token值
    local exists = ngx.shared.safewaf:get(token)
    if not exists then
        ngx.shared.safewaf:set(token, 0, fwsj)
    end

    -- 增加计数并获取当前值
    local count, err = ngx.shared.safewaf:incr(token, 1)
    if not count then
        -- 如果incr失败，重新设置并获取
        ngx.shared.safewaf:set(token, 1, fwsj)
        count = 1
    end
    -- 检查是否超过阈值
    if count > fwcs then
        -- 执行响应动作
        Helpers.logs('目录扫描防御：' .. ' URL：' .. uri .. ' IP：' .. ip .. ' 计数：' .. count)
        Dbs.xlog_time(GJLX['CONF_MOD_DEF_DIR_SCAN'], I18N['CONF_MOD_DEF_DIR_SCAN'], I18N['CONF_MOD_DEF_DIR_SCAN_MSG'], '', 300)
        IpInfo.ipblack_add(ip, 300)
        Helpers.return_html(503, SAFEWAF_RULES.limit_html)

        return true
    end

    return false
end

return conf_mod_cc_def
