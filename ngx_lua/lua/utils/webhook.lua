local webhook = {}


function webhook.ack_dd_webhook(lan_type)
    if AckWebHook == nil then return false end
    local dd_webhook = AckWebHook['dd_webhook']
    if dd_webhook == nil then return false end
    local DD_SHELL_ABS_PATH = SAFEWAF_SHELL .. "/dd_talk.sh" -- 改成真实绝对路径
    if not dd_webhook['open'] then return false end

    local DINGTALK_URL = dd_webhook['url']
    local SECRET = dd_webhook['secret']
    if DINGTALK_URL == nil or DINGTALK_URL == '' then return false end

    local suo = 'suo_dd_webhook_' .. ngx.ctx.ip
    if ngx.shared.safewaf:get(suo) then return false end

    local CONTENT = webhook.get_ack_msg(lan_type)

    local exec_cmd = string.format(
        "(%s %s '%s' '%s' >/dev/null 2>&1)",
        DD_SHELL_ABS_PATH, DINGTALK_URL, SECRET, CONTENT
    )
    ngx.shared.safewaf:set(suo, 1, 300) -- 300秒内不重复发送
    pcall(os.execute, exec_cmd)
end

function webhook.ack_http_webhook(lan_type)
    if AckWebHook == nil then return false end
    local http_webhook = AckWebHook['http_webhook']
    if http_webhook == nil then return false end
    local DD_SHELL_ABS_PATH = SAFEWAF_SHELL .. "/http_talk.sh" -- 改成真实绝对路径
    if not http_webhook['open'] then return false end

    local DINGTALK_URL = http_webhook['url']
    if DINGTALK_URL == nil or DINGTALK_URL == '' then return false end

    local suo = 'suo_http_webhook_' .. ngx.ctx.ip
    if ngx.shared.safewaf:get(suo) then return false end

    local CONTENT = webhook.get_ack_json(lan_type)

    local exec_cmd = string.format(
        "(%s %s '%s' >/dev/null 2>&1)",
        DD_SHELL_ABS_PATH, DINGTALK_URL, CONTENT
    )
    ngx.shared.safewaf:set(suo, 1, 300) -- 300秒内不重复发送
    pcall(os.execute, exec_cmd)
end

function webhook.get_ack_msg(lan_type)
    local headers = ngx.req.get_headers(20000)
    local headers_host = ''
    if not headers or headers.host == nil then
        headers_host = ''
    else
        headers_host = headers.host
    end

    local method = ngx.req.get_method()

    if Lang == "zh-CN" then
        local AREA = ""
        local area_list = {
            ngx.ctx.ip_dazhou,
            ngx.ctx.country,
            ngx.ctx.ip_province,
            ngx.ctx.ip_city,
            ngx.ctx.ip_area
        }
        for _, val in ipairs(area_list) do
            if val and val ~= "" and val ~= "nil" then
                AREA = AREA .. (AREA == "" and "" or "-") .. val
            end
        end

        local msg = "【WAF】已拦截\n" ..
            "【攻击IP】" .. ngx.ctx.ip .. "\n" ..
            "【攻击类型】" .. lan_type .. "\n" ..
            "【攻击时间】" .. ngx.ctx.local_time .. "\n" ..
            "【站点名称】" .. ngx.ctx.server_name .. "\n" ..
            "【请求类型】" .. method .. "\n" ..
            "【HOST】" .. headers_host .. "\n" ..
            "【请求网址】" .. headers_host .. ngx.var.request_uri .. "\n" ..
            "【归属地】" .. AREA .. "\n" ..
            "【ISP】" .. ngx.ctx.ip_isp .. "\n"
        return msg
    else
        local AREA = ""
        local area_list = {
            SAFEWAF_RULES.reg_en[ngx.ctx.ip_dazhou],
            SAFEWAF_RULES.reg_en[ngx.ctx.country],
            SAFEWAF_RULES.reg_en[ngx.ctx.ip_province],
            SAFEWAF_RULES.reg_en[ngx.ctx.ip_city],
        }
        for _, val in ipairs(area_list) do
            if val and val ~= "" and val ~= "nil" then
                AREA = AREA .. (AREA == "" and "" or "-") .. val
            end
        end

        local msg = "【WAF】INTERCEPTED\n" ..
            "【ATTACK IP】" .. ngx.ctx.ip .. "\n" ..
            "【ATTACK TYPE】" .. lan_type .. "\n" ..
            "【ATTACK TIME】" .. ngx.ctx.local_time .. "\n" ..
            "【SITE NAME】" .. ngx.ctx.server_name .. "\n" ..
            "【REQUEST TYPE】" .. method .. "\n" ..
            "【HOST】" .. headers_host .. "\n" ..
            "【REQUEST URL】" .. headers_host .. ngx.var.request_uri .. "\n" ..
            "【LOCATION】" .. AREA .. "\n" .. "\n"
        return msg
    end
end

function webhook.get_ack_json(lan_type)
    local headers = ngx.req.get_headers(20000)
    local headers_host = ''
    if not headers or headers.host == nil then
        headers_host = ''
    else
        headers_host = headers.host
    end

    local method = ngx.req.get_method()

    if Lang == "zh-CN" then
        local AREA = ""
        local area_list = {
            ngx.ctx.ip_dazhou,
            ngx.ctx.country,
            ngx.ctx.ip_province,
            ngx.ctx.ip_city,
            ngx.ctx.ip_area
        }
        for _, val in ipairs(area_list) do
            if val and val ~= "" and val ~= "nil" then
                AREA = AREA .. (AREA == "" and "" or "-") .. val
            end
        end

        local msg = {
            msg = "【WAF】已拦截", -- 固定值
            attack_ip = ngx.ctx.ip, -- 从 ngx 上下文取攻击IP
            attack_type = lan_type, -- 攻击类型变量
            attack_time = ngx.ctx.local_time, -- 攻击时间
            site_name = ngx.ctx.server_name, -- 站点名称
            request_type = method, -- 请求方法（GET/POST等）
            host = headers_host, -- 请求Host
            request_url = headers_host .. ngx.var.request_uri, -- 完整请求URL
            location = AREA -- IP地域信息
        }
        return Json.encode(msg)
    else
        local AREA = ""
        local area_list = {
            SAFEWAF_RULES.reg_en[ngx.ctx.ip_dazhou],
            SAFEWAF_RULES.reg_en[ngx.ctx.country],
            SAFEWAF_RULES.reg_en[ngx.ctx.ip_province],
            SAFEWAF_RULES.reg_en[ngx.ctx.ip_city],
        }
        for _, val in ipairs(area_list) do
            if val and val ~= "" and val ~= "nil" then
                AREA = AREA .. (AREA == "" and "" or "-") .. val
            end
        end

        local msg = {
            msg = "【WAF】INTERCEPTED", -- 固定值
            attack_ip = ngx.ctx.ip, -- 从 ngx 上下文取攻击IP
            attack_type = lan_type, -- 攻击类型变量
            attack_time = ngx.ctx.local_time, -- 攻击时间
            site_name = ngx.ctx.server_name, -- 站点名称
            request_type = method, -- 请求方法（GET/POST等）
            host = headers_host, -- 请求Host
            request_url = headers_host .. ngx.var.request_uri, -- 完整请求URL
            location = AREA -- IP地域信息
        }
        return Json.encode(msg)
    end
end

return webhook
