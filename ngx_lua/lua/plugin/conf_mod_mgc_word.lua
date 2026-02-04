-- 敏感词
local conf_mod_mgc_word = {}
local ngx_match = ngx.re.find

-- 响应脱敏
function conf_mod_mgc_word.body_def_resp_xytm()
    local mod_name = 'def_resp_xytm'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local rdata = mod_conf['conf']['sz']
    local mgxxjc = rdata['mgxxjc'] -- 敏感信息检测
    local mgwzth = rdata['mgwzth'] -- 敏感文字替换规则

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    local whole = ""
    local chunk, eof = ngx.arg[1], ngx.arg[2]
    local buffered = ngx.ctx.buffered
    if not buffered then
        buffered = {}
        ngx.ctx.buffered = buffered
    end
    if chunk ~= "" then
        buffered[#buffered + 1] = chunk
        ngx.arg[1] = nil
    end
    if eof then
        whole = table.concat(buffered)
        if #whole > 1024000 then
            ngx.arg[1] = whole
            return false
        end
        ngx.ctx.buffered = nil

        -- start
        if mgxxjc then
            if ngx.re.match(whole, "MySQL server", "ijo") then
                if ngx.re.match(whole, "MySQL|ODBC", "ijo") then
                    Helpers.logs('响应脱敏 ' .. uri .. ' IP：' .. ip)
                    Dbs.xlog(GJLX['CONF_MOD_DEF_RESP_XYTM'], I18N['CONF_MOD_DEF_RESP_XYTM'], I18N['CONF_MOD_DEF_RESP_XYTM_MSG'], '')
                    ngx.arg[1] = Helpers.return_404()
                    return true
                end
            end
        end
        if Helpers.arrlen(mgwzth) > 0 then
            -- 敏感文字>替换文字，一行一个
            for _, v in ipairs(mgwzth) do
                local wb = Helpers.split(v, '>')
                if not wb then goto continue end
                if Helpers.arrlen(wb) ~= 2 then goto continue end

                local gjc1 = wb[1]
                local gjc2 = wb[2]

                whole = ngx.re.gsub(whole, gjc1, gjc2, 'ijo')
                ngx.arg[1] = whole

                ::continue::
            end
        end
        -- end
        ngx.arg[1] = whole
    end

    return false
end

-- 请求敏感词拦截 URL级参数过滤
function conf_mod_mgc_word.def_req_lj_urlcsgl()
    local mod_name = 'def_req_lj'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local rdata = mod_conf['conf']['urlcsgl']
    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    for _, v in ipairs(rdata) do
        local is_match_url = false
        if v.pp_mode == 1 then
            -- 完全匹配
            is_match_url = (uri == v.url)
        elseif v.pp_mode == 2 then
            -- 正则匹配
            is_match_url = ngx_match(uri, v.url, 'jo') ~= nil
        end
        if not is_match_url then goto continue end

        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        local get_args = ngx.var.args

        if get_args ~= nil and #get_args > 0 then
            if ngx.re.match(get_args, v.gjc, 'ijo') then
                Helpers.logs('请求敏感词拦截 URL级参数过滤 ' .. uri .. ' IP：' .. ip)
                Dbs.xlog(GJLX['CONF_MOD_DEF_REQ_LJ'], I18N['CONF_MOD_DEF_REQ_LJ'], I18N['CONF_MOD_DEF_REQ_LJ_URLCSGL_MSG'], '')
                Helpers.return_html(503, SAFEWAF_RULES.get_html)
                return true
            end
        end
        if body ~= nil and #body > 0 then
            if ngx.re.match(body, v.gjc, 'ijo') then
                Helpers.logs('请求敏感词拦截 URL级参数过滤 ' .. uri .. ' IP：' .. ip)
                Dbs.xlog(GJLX['CONF_MOD_DEF_REQ_LJ'], I18N['CONF_MOD_DEF_REQ_LJ'], I18N['CONF_MOD_DEF_REQ_LJ_URLCSGL_MSG'], '')
                Helpers.return_html(503, SAFEWAF_RULES.get_html)
                return true
            end
        end

        ::continue::
    end

    return false
end

-- 请求敏感词拦截 违禁词
function conf_mod_mgc_word.def_req_lj_wjc()
    local mod_name = 'def_req_lj'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local rdata = mod_conf['conf']['wjc']
    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    for _, v in ipairs(rdata) do
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        local get_args = ngx.var.args
        if get_args ~= nil and #get_args > 0 then
            if ngx.re.match(ngx.unescape_uri(get_args), v, 'ijo') then
                Helpers.logs('请求敏感词拦截 违禁词 ' .. uri .. ' IP：' .. ip)
                Dbs.xlog(GJLX['CONF_MOD_DEF_REQ_LJ'], I18N['CONF_MOD_DEF_REQ_LJ'], I18N['CONF_MOD_DEF_REQ_LJ_WJC_MSG'], '')
                Helpers.return_html(503, SAFEWAF_RULES.get_html)
                return true
            end
        end
        if body ~= nil and #body > 0 then
            if ngx.re.match(body, v, 'ijo') then
                Helpers.logs('请求敏感词拦截 违禁词 ' .. uri .. ' IP：' .. ip)
                Dbs.xlog(GJLX['CONF_MOD_DEF_REQ_LJ'], I18N['CONF_MOD_DEF_REQ_LJ'], I18N['CONF_MOD_DEF_REQ_LJ_WJC_MSG'], '')
                Helpers.return_html(503, SAFEWAF_RULES.get_html)
                return true
            end
        end

        ::continue::
    end

    return false
end

return conf_mod_mgc_word
