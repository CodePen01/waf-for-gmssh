-- 请求合规防御
local conf_mod_req_hg = {}
local ngx_match = ngx.re.find

-- 静态文件防护
function conf_mod_req_hg.def_robot()
    local mod_name = 'def_robot'
    local fwsj = 60
    local fwcs = 3

    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri

    -- 检查是否为机器人
    if not Helpers.check_rebot() then return false end

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
        Helpers.logs('机器人防护：' .. ' URL：' .. uri .. ' IP：' .. ip .. ' 计数：' .. count)

        Dbs.xlog_time(GJLX['CONF_MOD_DEF_ROBOT'], I18N['CONF_MOD_DEF_ROBOT'], I18N['CONF_MOD_DEF_ROBOT_MSG'], '', 300)
        IpInfo.ipblack_add(ip, 300)
        Helpers.return_html(503, SAFEWAF_RULES.limit_html)

        return true
    end

    return false
end

-- 请求类型过滤
function conf_mod_req_hg.def_http_req_qqlx()
    local mod_name = 'def_http_req'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local rdata = mod_conf['conf']['qqlx']
    local method = ngx.req.get_method()
    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    for _, v in ipairs(rdata) do
        -- 检查URL匹配
        Helpers.logs(uri)
        Helpers.logs(v.url)
        Helpers.logs(method)
        if uri ~= v.url then goto continue end
        local qqlx_list = Helpers.split(v.qqlx, ',')
        if not Helpers.in_list(method, qqlx_list) then
            Helpers.logs('请求类型过滤' .. ' URL：' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ_QQLX_MSG'], '')
            Helpers.return_html(503, SAFEWAF_RULES.get_html)
        end

        ::continue::
    end

    return false
end

-- 请求头过滤
function conf_mod_req_hg.def_http_req_qqt()
    local mod_name = 'def_http_req'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local rdata = mod_conf['conf']['qqt']
    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    local headers = ngx.req.get_headers()
    for _, v in ipairs(rdata) do
        -- 判断v.qqt是否在header中 da包含v.qqt
        if not headers[v.qqt] then goto continue end
        -- 判断v.qqt大小是否大于v.dx
        if #headers[v.qqt] > v.dx then
            Helpers.logs('请求头过滤' .. ' URL：' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ_QQT_MSG'], '')
            Helpers.return_html(503, SAFEWAF_RULES.get_html)
        end

        ::continue::
    end

    return false
end

-- 请求数量过滤
function conf_mod_req_hg.def_http_req_qqsl()
    local mod_name = 'def_http_req'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local qqsl = mod_conf['conf']['qqsl']
    local jm_base64 = qqsl['jm_base64']     -- 解析 base64 加密字符串
    local cszdcd = qqsl['cszdcd']           -- 参数最大长度
    local post_cszdsl = qqsl['post_cszdsl'] -- Post参数最大数量
    local get_cszdsl = qqsl['get_cszdsl']   -- Get参数最大数量

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    local method = ngx.req.get_method()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local args = ngx.var.args

    -- 判断args或bodys 大小是否大于cszdcd
    if args ~= nil and #args > cszdcd then
        Helpers.logs('请求数量过滤' .. ' URL：' .. uri .. ' IP：' .. ip)
        Dbs.xlog(GJLX['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ_QQSL_MSG'], '')
        Helpers.return_html(503, SAFEWAF_RULES.get_html)
    end
    if body ~= nil and #body > cszdcd then
        Helpers.logs('请求数量过滤' .. ' URL：' .. uri .. ' IP：' .. ip)
        Dbs.xlog(GJLX['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ_QQSL_MSG'], '')
        Helpers.return_html(503, SAFEWAF_RULES.get_html)
    end

    -- 检查Get参数数量
    if method == 'GET' then
        local get_args = ngx.req.get_uri_args()
        if Helpers.arrlen(get_args) > get_cszdsl then
            Helpers.logs('请求数量过滤' .. ' URL：' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ_QQSL_MSG'], '')
            Helpers.return_html(503, SAFEWAF_RULES.get_html)
        end
    elseif method == 'POST' then
        local post_args = ngx.req.get_post_args()
        if Helpers.arrlen(post_args) > post_cszdsl then
            Helpers.logs('请求数量过滤' .. ' URL：' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ_QQSL_MSG'], '')
            Helpers.return_html(503, SAFEWAF_RULES.get_html)
        end
        if body ~= nil then
            local count = select(2, ngx.re.gsub(body, 'Content-Disposition', "", "jo"))
            if count > post_cszdsl then
                Helpers.logs('请求数量过滤' .. ' URL：' .. uri .. ' IP：' .. ip)
                Dbs.xlog(GJLX['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ_QQSL_MSG'], '')
                Helpers.return_html(503, SAFEWAF_RULES.get_html)
            end
            if jm_base64 then
                local jm_body = ngx.decode_base64(body)
                if jm_body ~= nil then
                    local count = Helpers.arrlen(Helpers.split(jm_body, '&'))
                    if count > post_cszdsl then
                        Helpers.logs('请求数量过滤' .. ' URL：' .. uri .. ' IP：' .. ip)
                        Dbs.xlog(GJLX['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ'], I18N['CONF_MOD_DEF_HTTP_REQ_QQSL_MSG'], '')
                        Helpers.return_html(503, SAFEWAF_RULES.get_html)
                    end
                end
            end
        end
    end

    return false
end

-- 禁止国内外访问
function conf_mod_req_hg.def_gnw_fw()
    local mod_name = 'def_gnw_fw'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local gn_xyym = mod_conf['conf']['gn']['xyym']
    local gn_ip_list = mod_conf['conf']['gn']['ip_list']

    local gw_xyym = mod_conf['conf']['gw']['xyym']
    local gw_ip_list = mod_conf['conf']['gw']['ip_list']

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    if Helpers.arrlen(gn_ip_list) > 0 then
        for _, rule in ipairs(gn_ip_list) do
            if IpInfo.is_ip_in_range(ip, rule) then
                Helpers.logs('禁止国内外访问 禁止国内IP访问' .. ' URL：' .. uri .. ' IP：' .. ip)
                Dbs.xlog(GJLX['CONF_MOD_DEF_GNW_FW'], I18N['CONF_MOD_DEF_GNW_FW'], I18N['CONF_MOD_DEF_GNW_FW_MSG'], '')
                Helpers.return_html(gn_xyym, SAFEWAF_RULES.ip_html)
            end
        end
    end
    if Helpers.arrlen(gw_ip_list) > 0 then
        for _, rule in ipairs(gw_ip_list) do
            if IpInfo.is_ip_in_range(ip, rule) then
                Helpers.logs('禁止国内外访问 禁止国外IP访问' .. ' URL：' .. uri .. ' IP：' .. ip)
                Dbs.xlog(GJLX['CONF_MOD_DEF_GNW_FW'], I18N['CONF_MOD_DEF_GNW_FW'], I18N['CONF_MOD_DEF_GNW_FW_MSG'], '')
                Helpers.return_html(gw_xyym, SAFEWAF_RULES.ip_html)
            end
        end
    end

    return false
end

return conf_mod_req_hg
