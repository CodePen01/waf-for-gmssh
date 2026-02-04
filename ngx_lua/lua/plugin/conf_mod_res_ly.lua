-- 防资源滥用
local conf_mod_res_ly = {}
local ngx_match = ngx.re.find

-- 恶意下载防御
function conf_mod_res_ly.def_down()
    local mod_name = 'def_down'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local xyym = mod_conf['xyym']
    local rdata = mod_conf['conf']['list']

    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    local request_uri = ngx.var.request_uri
    for _, v in ipairs(rdata) do
        if not v.open then goto continue end
        if request_uri ~= nil and ngx_match(request_uri, v.rule, 'ijo') then
            Helpers.logs('恶意下载防御：' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_DOWN'], I18N['CONF_MOD_DEF_DOWN'], I18N['CONF_MOD_DEF_DOWN_MSG'], '')
            Helpers.return_html(xyym, SAFEWAF_RULES.get_html)
            return true
        end

        ::continue::
    end

    return false
end

-- URL保护防御 指定参数访问的URL
function conf_mod_res_ly.def_url_bh_zdcsfw()
    local mod_name = 'def_url_bh'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local rdata = mod_conf['conf']['zdcsfw']
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

        local get_args = ngx.req.get_uri_args()

        if Helpers.arrlen(get_args) > 0 then
            if get_args[v.csm] ~= nil and get_args[v.csm] == v.csz then
                goto continue
            end
        end

        ngx.req.read_body()
        local post_args = ngx.req.get_post_args()
        local body = ngx.req.get_body_data()
        if Helpers.arrlen(post_args) > 0 then
            if post_args[v.csm] ~= nil and post_args[v.csm] == v.csz then
                goto continue
            end
        end
        if body ~= nil then
            local count = select(2, ngx.re.gsub(body, 'Content-Disposition', "", "jo"))
            if count > 0 then
                local pattern = [[name="]] .. v.csm .. [["\s*]] .. v.csz
                local is_match = ngx_match(body, pattern, "ijo")
                if is_match then
                    goto continue
                end
            end
        end

        Helpers.logs('指定参数访问的URL ' .. uri .. ' IP：' .. ip)
        Dbs.xlog(GJLX['CONF_MOD_DEF_URL_BH'], I18N['CONF_MOD_DEF_URL_BH'], I18N['CONF_MOD_DEF_URL_BH_ZDCSFW_MSG'], '')
        Helpers.return_html(503, SAFEWAF_RULES.get_html)

        ::continue::
    end

    return false
end

-- URL保护防御 禁止执行PHP的URL
function conf_mod_res_ly.def_url_bh_jzzxphp()
    local mod_name = 'def_url_bh'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local rdata = mod_conf['conf']['jzzxphp']
    if Helpers.arrlen(rdata) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    for _, v in ipairs(rdata) do
        -- 判断uri中包含v, 且以.php结尾
        if string.find(uri, v) and string.match(uri, "%.php$") then
            Helpers.logs('禁止执行PHP的URL ' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_URL_BH'], I18N['CONF_MOD_DEF_URL_BH'], I18N['CONF_MOD_DEF_URL_BH_JZZXPHP_MSG'], '')
            Helpers.return_html(503, SAFEWAF_RULES.get_html)
        end

        ::continue::
    end

    return false
end

-- 恶意文件上传防御 启用标准上传格式校验
function conf_mod_res_ly.def_upload_scgsyx(body)
    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    local content_type = ngx.req.get_headers()["content-type"]
    if content_type and string.find(string.lower(content_type), "multipart/form-data", 1, true) then
        local boundary = string.match(content_type, "boundary=(.-)$")
        if not boundary then
            Helpers.logs('标准上传格式校验失败: No boundary in header ' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_UPLOAD'], I18N['CONF_MOD_DEF_UPLOAD'], I18N['CONF_MOD_DEF_UPLOAD_SCGSYX_MSG'], '')
            Helpers.return_html(503, SAFEWAF_RULES.get_html)
            return true
        end
        if not string.find(body, "--" .. boundary, 1, true) then
            Helpers.logs('标准上传格式校验失败: Boundary mismatch ' .. uri .. ' IP：' .. ip)
            Dbs.xlog(GJLX['CONF_MOD_DEF_UPLOAD'], I18N['CONF_MOD_DEF_UPLOAD'], I18N['CONF_MOD_DEF_UPLOAD_SCGSYX_MSG'], '')
            Helpers.return_html(503, SAFEWAF_RULES.get_html)
            return true
        end
    end
end

-- 恶意文件上传防御 禁止上传的扩展名
function conf_mod_res_ly.def_upload_jzsc(body, jzsc_list)
    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    local iterator, err = ngx.re.gmatch(body, 'filename="([^"]+)"', "ijo")
    if iterator then
        while true do
            local m, err = iterator()
            if not m then break end
            local filename = m[1]
            local ext = string.match(filename, "%.([^.]+)$")
            if ext then
                ext = "." .. string.lower(ext)
                for _, v in ipairs(jzsc_list) do
                    if string.lower(v) == ext then
                        Helpers.logs('禁止上传的扩展名: ' .. filename .. ' IP：' .. ip)
                        Dbs.xlog(GJLX['CONF_MOD_DEF_UPLOAD'], I18N['CONF_MOD_DEF_UPLOAD'], I18N['CONF_MOD_DEF_UPLOAD_JZSC_MSG'], '')
                        Helpers.return_html(503, SAFEWAF_RULES.get_html)
                        return true
                    end
                end
            end
        end
    end
end

-- 文件头检测
function conf_mod_res_ly.def_upload_wjtjc(body, wjtjc_list)
    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    local signatures = {
        [".php"] = "<?php",
        [".jsp"] = "<%",
        [".asp"] = "<%",
        [".exe"] = "MZ",
        [".sh"] = "#!",
        [".pl"] = "#!",
    }
    local start_pos = 1
    while true do
        local from, to, err = ngx.re.find(body, 'filename="([^"]+)"', "ijo", { pos = start_pos })
        if not from then break end

        local filename_match = string.sub(body, from, to)
        local filename = string.match(filename_match, 'filename="([^"]+)"')

        local content_from, content_to, err2 = ngx.re.find(body, "\r\n\r\n", "jo", { pos = to + 1 })
        if content_from then
            local content_start = content_to + 1
            -- 读取前30个字节进行模糊匹配，防止通过添加前缀绕过
            local header_bytes = string.sub(body, content_start, content_start + 30)

            for _, ext in ipairs(wjtjc_list) do
                local sig = signatures[ext]
                if sig and string.find(header_bytes, sig, 1, true) then
                    Helpers.logs('文件头检测失败: ' .. filename .. ' detected as ' .. ext .. ' IP：' .. ip)
                    Dbs.xlog(GJLX['CONF_MOD_DEF_UPLOAD'], I18N['CONF_MOD_DEF_UPLOAD'], I18N['CONF_MOD_DEF_UPLOAD_WJTJC_MSG'], '')
                    Helpers.return_html(503, SAFEWAF_RULES.get_html)
                    return true
                end
            end
        end
        start_pos = to + 1
    end
end

-- 恶意文件上传防御
function conf_mod_res_ly.def_upload()
    local mod_name = 'def_upload'
    local mod_conf = Helpers.get_mod_conf(mod_name)
    if not mod_conf then return false end
    if not mod_conf['open'] then return false end

    local rdata = mod_conf['conf']['sz']
    local scgsyx = rdata['scgsyx'] -- 启用标准上传格式校验
    local jzsc = rdata['jzsc']     -- 禁止上传的扩展名
    local wjtjc = rdata['wjtjc']   -- 文件头检测

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        local body_file = ngx.req.get_body_file()
        if body_file then
            -- 读取临时文件内容
            local file, err = io.open(body_file, "r")
            if file then
                body = file:read("*a") -- 读取全部内容
                file:close()
            else
                return false
            end
        end
    end
    if not body then return false end

    -- 1. 标准上传格式校验
    if scgsyx then
        conf_mod_res_ly.def_upload_scgsyx(body)
    end

    -- 2. 禁止上传的扩展名
    if jzsc and #jzsc > 0 then
        local jzsc_list = Helpers.split(jzsc, ",")
        if jzsc_list then
            conf_mod_res_ly.def_upload_jzsc(body, jzsc_list)
        end
    end

    -- 3. 文件头检测
    if wjtjc and #wjtjc > 0 then
        local wjtjc_list = Helpers.split(wjtjc, ",")
        if wjtjc_list then
            conf_mod_res_ly.def_upload_wjtjc(body, wjtjc_list)
        end
    end

    return false
end

return conf_mod_res_ly
