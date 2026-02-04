-- 防护规则 流量限制
local fhgz_llxz = {}
local ngx_match = ngx.re.find


function fhgz_llxz.check()
    local mod_name = 'fhgz_llxz'
    if Helpers.arrlen(SAFEWAF_RULES.waf_llxz) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    for _, v in ipairs(SAFEWAF_RULES.waf_llxz) do
        if not v.open then goto continue end
        local name_list = Helpers.split(v.name, ',')
        local is_match_name = Helpers.in_list(ngx.ctx.server_name, name_list)
        if not is_match_name then goto continue end

        -- 检查URL匹配
        local is_match_url = false
        if v.mode == 1 then
            -- 完全匹配
            is_match_url = (uri == v.url)
        elseif v.mode == 2 then
            -- 正则匹配
            is_match_url = ngx_match(uri, v.url, 'jo') ~= nil
        end
        if not is_match_url then goto continue end

        -- 生成token
        local token
        if v.wd == 1 then
            -- 统计维度 1: ip
            token = ngx.md5(mod_name .. ip)
        elseif v.wd == 2 then
            -- 统计维度 2: ip+url
            token = ngx.md5(mod_name .. ip .. uri)
        elseif v.wd == 3 then
            -- 统计维度 3: 全部ip
            token = ngx.md5(mod_name .. 'all_ip')
        end

        -- 初始化token值
        local exists = ngx.shared.safewaf:get(token)
        if not exists then
            ngx.shared.safewaf:set(token, 0, v.plsj)
        end

        -- 增加计数并获取当前值
        local count, err = ngx.shared.safewaf:incr(token, 1)
        if not count then
            -- 如果incr失败，重新设置并获取
            ngx.shared.safewaf:set(token, 1, v.plsj)
            count = 1
        end

        -- 检查是否超过阈值
        if count > v.pljc then
            -- 执行响应动作
            Helpers.logs('流量限制拦截：' .. v.rule_name .. ' URL：' .. uri .. ' IP：' .. ip .. ' 计数：' .. count)
            Dbs.xlog_time(GJLX['FHGZ_LLXZ'], I18N['FHGZ_LLXZ'], I18N['FHGZ_LLXZ_MSG'] .. ' (' .. v.rule_name .. ')', '', 300)

            if v.xydz == 1 then
                -- 封锁ip
                IpInfo.ipblack_add(ip, 300)
                ngx.exit(444)
            elseif v.xydz == 2 then
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

return fhgz_llxz
