-- 防护规则 自定义规则
local fhgz_diy_rule = {}

--只匹配参数名
function fhgz_diy_rule.Param_name(option)
    if option == nil or option == "" or option["operator"] == nil or option["operator"] == "" or option["right_factor"] == nil or option["right_factor"] == "" then return false end
    local right_factor = Helpers.split(option["right_factor"], ",")
    if right_factor == nil or right_factor == "" then return false end
    for _, v in ipairs(right_factor) do
        --包含
        if option["operator"] == "in" then
            if ngx.ctx.get_uri_args[v] == nil then
                return false
            end
            --不包含
        elseif option["operator"] == "not_in" then
            if ngx.ctx.get_uri_args[v] ~= nil then
                return false
            end
        end
    end

    return true
end

--请求参数的数量
function fhgz_diy_rule.Param_count(option)
    if option == nil or option == "" or option["operator"] == nil or option["operator"] == "" or option["right_factor"] == nil or option["right_factor"] == "" then return false end
    local check_count = tonumber(option["right_factor"])
    --大于
    if option["operator"] == "gt" then
        if ngx.ctx.uri_args_count > check_count then
            return true
        end
        --大于或等于
    elseif option["operator"] == "egt" then
        if ngx.ctx.uri_args_count >= check_count then
            return true
        end
        --小于
    elseif option["operator"] == "lt" then
        if ngx.ctx.uri_args_count < check_count then
            return true
        end
        --小于或等于
    elseif option["operator"] == "elt" then
        if ngx.ctx.uri_args_count <= check_count then
            return true
        end
        --等于
    elseif option["operator"] == "eq" then
        if ngx.ctx.uri_args_count == check_count then
            return true
        end
    end
    return false
end

--只匹配请求头名称
function fhgz_diy_rule.Request_header_name(option)
    if option == nil or option == "" or option["operator"] == nil or option["operator"] == "" or option["right_factor"] == nil or option["right_factor"] == "" then return false end
    --包含
    if option["operator"] == "in" then
        if ngx.ctx.request_header[option["right_factor"]] ~= nil then
            return true
        end
        --不包含
    elseif option["operator"] == "not_in" then
        if ngx.ctx.request_header[option["right_factor"]] == nil then
            return true
        end
        --其他情况
    else
        return false
    end
    return false
end

--匹配请求头名称和值
function fhgz_diy_rule.Request_header(option)
    if option == nil or option == "" or option["operator"] == nil or option["operator"] == "" or option["right_factor"] == nil or option["right_factor"] == "" or option["left_factor"] == nil or option["left_factor"] == "" then return false end
    if ngx.ctx.request_header == nil then return false end

    --匹配开头，不区分大小写
    if option["operator"] == "prefix" then
        if ngx.re.match(ngx.ctx.request_header[option["left_factor"]], "^" .. option["right_factor"], "isjo") then
            return true
        end
        --匹配结尾，不区分大小写
    elseif option["operator"] == "suffix" then
        if ngx.re.match(ngx.ctx.request_header[option["left_factor"]], option["right_factor"] .. "$", "isjo") then
            return true
        end
        --等于/完全匹配（不区分大小写）
    elseif option["operator"] == "eq" then
        if ngx.ctx.request_header[option["left_factor"]] == option["right_factor"] then
            return true
        end
        --不等于（不区分大小写）
    elseif option["operator"] == "neq" then
        if ngx.ctx.request_header[option["left_factor"]] ~= option["right_factor"] then
            return true
        end
        --模糊匹配（不区分大小写）
    elseif option["operator"] == "like" then
        if ngx.ctx.request_header[option["left_factor"]] ~= nil and ngx.re.match(ngx.ctx.request_header[option["left_factor"]], option["right_factor"], "isjo") then
            return true
        end
    end
    return false
end

--匹配请求头的数量
function fhgz_diy_rule.Request_header_count(option)
    if option == nil or option == "" or option["operator"] == nil or option["operator"] == "" or option["right_factor"] == nil or option["right_factor"] == "" then return false end
    local check_count = tonumber(option["right_factor"])
    --等于
    if option["operator"] == "eq" then
        if ngx.ctx.request_header_count == check_count then
            return true
        end
        --大于
    elseif option["operator"] == "gt" then
        if ngx.ctx.request_header_count > check_count then
            return true
        end
        --大于或等于
    elseif option["operator"] == "egt" then
        if ngx.ctx.request_header_count >= check_count then
            return true
        end
        --小于
    elseif option["operator"] == "lt" then
        if ngx.ctx.request_header_count < check_count then
            return true
        end
        --小于或等于
    elseif option["operator"] == "elt" then
        if ngx.ctx.request_header_count <= check_count then
            return true
        end
    end
end

--匹配ip
function fhgz_diy_rule.Ip(option)
    if option == nil or option == "" or option["operator"] == nil or option["operator"] == "" or option["right_factor"] == nil or option["right_factor"] == "" then return false end
    --等于
    if option["operator"] == "eq" then
        if ngx.ctx.ip == option["right_factor"] then
            return true
        end
        --不等于
    elseif option["operator"] == "neq" then
        if ngx.ctx.ip ~= option["right_factor"] then
            return true
        end
    end
    return false
end

--匹配ip段
function fhgz_diy_rule.Ip_range(option)
    if option == nil or option == "" or option["operator"] == nil or option["operator"] == "" or option["right_factor"] == nil or option["right_factor"] == "" then return false end

    local ip_range = IpTools.new({ option["right_factor"] })
    if ip_range == nil then return false end
    if ip_range:match(ngx.ctx.ip) then
        return true
    end
    return false
end

--匹配User_agent
function fhgz_diy_rule.User_agent(option)
    if option == nil or option == "" or option["operator"] == nil or option["operator"] == "" or option["right_factor"] == nil or option["right_factor"] == "" then return false end
    --以,号分隔option["right_factor"]的值
    local right_factor = Helpers.split(option["right_factor"], "|")
    if right_factor == nil or right_factor == "" then return false end
    local flag = true
    for _, v in ipairs(right_factor) do
        --等于
        if option["operator"] == "eq" then
            if v == ngx.ctx.ua then
                return true
            end
            --为空
        elseif option["operator"] == "null" then
            if ngx.ctx.ua == "waf_null" then
                return true
            end
            --不等于
        elseif option["operator"] == "neq" then
            if v ~= ngx.ctx.ua then
                return true
            end
            --包含
        elseif option["operator"] == "in" then
            if v == ngx.ctx.ua then
                return true
            end
            --不包含
        elseif option["operator"] == "not_in" then
            if v == ngx.ctx.ua then
                return false
            end
            -- 长度小于或等于 elt_len
        elseif option["operator"] == "elt_len" then
            if #ngx.ctx.ua <= tonumber(v) then
                return true
            end
            --模糊匹配
        elseif option["operator"] == "like" then
            if ngx.re.match(ngx.ctx.ua, v, "isjo") then
                return true
            end
        end
    end
    if flag and option["operator"] == "not_in" then return true end
    return false
end

--匹配referer
function fhgz_diy_rule.Referer(option)
    if option == nil or option == "" or option["operator"] == nil or option["operator"] == "" or option["right_factor"] == nil or option["right_factor"] == "" or ngx.ctx.referer == nil then return false end
    --以,号分隔option["right_factor"]的值
    local right_factor = Helpers.split(option["right_factor"], ",")
    if right_factor == nil or right_factor == "" then return false end
    local flag = true
    for _, v in ipairs(right_factor) do
        --正则表达式，不区分大小写
        if option["operator"] == "regexp" then
            if ngx.re.match(ngx.ctx.referer, v, "isjo") then
                return true
            end
        elseif option["operator"] == "null" then
            if ngx.ctx.referer == "waf_referer_null" then
                return true
            end
            --匹配开头，不区分大小写
        elseif option["operator"] == "prefix" then
            if ngx.re.match(ngx.ctx.referer, "^" .. v, "isjo") then
                return true
            end
            --匹配结尾，不区分大小写
        elseif option["operator"] == "suffix" then
            if ngx.re.match(ngx.ctx.referer, v .. "$", "isjo") then
                return true
            end
            --等于
        elseif option["operator"] == "eq" then
            if v == ngx.ctx.referer then
                return true
            end
            --不等于
        elseif option["operator"] == "neq" then
            if v ~= ngx.ctx.referer then
                return true
            end
            --包含
        elseif option["operator"] == "in" then
            if v == ngx.ctx.referer then
                return true
            end
            --不包含
        elseif option["operator"] == "not_in" then
            if v == ngx.ctx.referer then
                return false
            end
        end
    end
    if flag and option["operator"] == "not_in" then return true end
    return false
end

--匹配 地级市
function fhgz_diy_rule.Ip_city(option)
    if option == nil or option == "" or option["operator"] == nil or option["operator"] == "" or option["right_factor"] == nil or option["right_factor"] == "" then return false end
    local overall_country = ngx.ctx.ip_city
    if overall_country == nil or overall_country == "" then return false end
    local right_factor = Helpers.split(option["right_factor"], ",")
    if right_factor == nil or right_factor == "" then return false end
    -- 等于的时候
    if option["operator"] == "eq" then
        for _, v in ipairs(right_factor) do
            if overall_country == v then
                return true
            end
        end
    end
    return false
end

--匹配ip 省份、直辖市、自治区
function fhgz_diy_rule.Ip_province(option)
    if option == nil or option == "" or option["operator"] == nil or option["operator"] == "" or option["right_factor"] == nil or option["right_factor"] == "" then return false end
    local overall_country = ngx.ctx.ip_province
    if overall_country == nil or overall_country == "" then return false end
    local right_factor = Helpers.split(option["right_factor"], ",")
    if right_factor == nil or right_factor == "" then return false end
    -- 等于的时候
    if option["operator"] == "eq" then
        for _, v in ipairs(right_factor) do
            if overall_country == v then
                return true
            end
        end
    end
    return false
end

--匹配ip地区
function fhgz_diy_rule.Ip_area(option)
    if option == nil or option == "" or option["operator"] == nil or option["operator"] == "" or option["right_factor"] == nil or option["right_factor"] == "" then return false end
    local overall_country = ngx.ctx.country
    if overall_country == nil or overall_country == "" then return false end
    --以,号分隔option["right_factor"]的值
    if overall_country == "内网地址" then return false end
    local right_factor = Helpers.split(option["right_factor"], ",")
    if right_factor == nil or right_factor == "" then return false end
    --遍历right_factor的值
    local flag = false

    -- 等于的时候
    if option["operator"] == "eq" then
        for _, v in ipairs(right_factor) do
            if v == "中国以外地区" then
                if overall_country ~= "中国" then
                    return true
                end
            end
            if overall_country == v then
                return true
            end
        end
    elseif option["operator"] == "neq" then
        for _, v in ipairs(right_factor) do
            if v == "中国以外地区" then
                if overall_country == "中国" then
                    return false
                end
            else
                if overall_country == v then
                    return false
                end
            end
        end
        return true
    end
    return false
end

--匹配参数名和值
function fhgz_diy_rule.Param(option)
    if option == nil or option == "" or option["left_factor"] == "" or option["left_factor"] == nil or option["right_factor"] == "" or option["right_factor"] == nil then return false end
    --正则表达式，不区分大小写
    if option["operator"] == "regexp" then
        if ngx.re.match(ngx.ctx.get_uri_args[option["left_factor"]], option["right_factor"], "isjo") then
            return true
        end
        --匹配开头，不区分大小写
    elseif option["operator"] == "prefix" then
        if ngx.re.match(ngx.ctx.get_uri_args[option["left_factor"]], "^" .. option["right_factor"], "isjo") then
            return true
        end
        --匹配结尾，不区分大小写
    elseif option["operator"] == "suffix" then
        if ngx.re.match(ngx.ctx.get_uri_args[option["left_factor"]], option["right_factor"] .. "$", "isjo") then
            return true
        end
        --等于/完全匹配（不区分大小写）
    elseif option["operator"] == "eq" then
        if ngx.ctx.get_uri_args[option["left_factor"]] == option["right_factor"] then
            return true
        end
        --不等于（不区分大小写）
    elseif option["operator"] == "neq" then
        if ngx.ctx.get_uri_args[option["left_factor"]] ~= option["right_factor"] then
            return true
        end
        --模糊匹配（不区分大小写）
    elseif option["operator"] == "like" then
        if ngx.re.match(ngx.ctx.get_uri_args[option["left_factor"]], option["right_factor"], "isjo") then
            return true
        end
    end
    return false
end

--匹配uri 不带参数/带参数
function fhgz_diy_rule.Uri(option)
    if option == nil or option == "" or option["right_factor"] == "" or option["right_factor"] == nil then return false end
    local uri = ngx.ctx.url_split
    if option["type"] == "uri_with_param" then uri = ngx.var.request_uri end
    if option["type"] == "uri_param" then
        uri = ngx.ctx.url_split[2]
    end
    if uri == nil or uri == "" then return false end
    --正则表达式，不区分大小写
    if option["operator"] == "regexp" then
        if ngx.re.match(uri, option["right_factor"], "isjo") then
            return true
        end
        --匹配开头，不区分大小写
    elseif option["operator"] == "prefix" then
        if ngx.re.match(uri, "^" .. option["right_factor"], "isjo") then
            return true
        end
        --匹配结尾，不区分大小写
    elseif option["operator"] == "suffix" then
        if ngx.re.match(uri, option["right_factor"] .. "$", "isjo") then
            return true
        end
        --等于/完全匹配（不区分大小写）
    elseif option["operator"] == "eq" then
        if uri == option["right_factor"] then
            return true
        end
        --不等于（不区分大小写）
    elseif option["operator"] == "neq" then
        if uri ~= option["right_factor"] then
            return true
        end
        --模糊匹配（不区分大小写）
    elseif option["operator"] == "like" then
        if ngx.re.match(uri, option["right_factor"], "isjo") then
            return true
        end
        --包含（不区分大小写）
    elseif option["operator"] == "in" then
        local right_factor = Helpers.split(option["right_factor"], ",")
        if right_factor == nil or right_factor == "" then return false end
        for _, v in ipairs(right_factor) do
            if uri == v then
                return true
            end
        end
        --不包含（不区分大小写）
    elseif option["operator"] == "not_in" then
        local right_factor = Helpers.split(option["right_factor"], ",")
        if right_factor == nil or right_factor == "" then return false end
        for _, v in ipairs(right_factor) do
            if uri == v then
                return false
            end
        end
        return true
    end
    return false
end

-- 匹配请求方法
function fhgz_diy_rule.Request_method(option)
    if option == nil or option == "" or option["right_factor"] == "" or option["right_factor"] == nil then return false end
    --遍历right_factor的值

    --等于
    if option["operator"] == "eq" then
        if ngx.ctx.method == option["right_factor"] then
            return true
        end
        --不等于
    elseif option["operator"] == "neq" then
        if ngx.ctx.method ~= option["right_factor"] then
            return true
        end
        --包含
    elseif option["operator"] == "in" then
        local right_factor = Helpers.split(option["right_factor"], ",")
        if right_factor == nil or right_factor == "" then return false end
        for _, v in ipairs(right_factor) do
            if ngx.ctx.method == v then
                return true
            end
        end
        --不包含
    elseif option["operator"] == "not_in" then
        local right_factor = Helpers.split(option["right_factor"], ",")
        if right_factor == nil or right_factor == "" then return false end
        for _, v in ipairs(right_factor) do
            if ngx.ctx.method == v then
                return false
            end
        end
        return true
    end
    return false
end

-- 匹配请求头
function fhgz_diy_rule.Request_head(request_head, request_head_value, match_type)
    if request_head ~= nil and request_head ~= "" and request_head_value ~= nil and request_head_value ~= "" and match_type ~= nil and match_type ~= "" then
        --等于
        if match_type == "eq" then
            if ngx.ctx.request_header[request_head] == request_head_value then
                return true
            end
            --不等于
        elseif match_type == "neq" then
            if ngx.ctx.request_header[request_head] ~= request_head_value then
                return true
            end
            --匹配开头，不区分大小写
        elseif match_type == "prefix" then
            if ngx.re.match(ngx.ctx.request_header[request_head], "^" .. request_head_value, "isjo") then
                return true
            end
            --匹配结尾，不区分大小写
        elseif match_type == "suffix" then
            if ngx.re.match(ngx.ctx.request_header[request_head], request_head_value .. "$", "isjo") then
                return true
            end
            --模糊匹配（不区分大小写）
        elseif match_type == "like" then
            if ngx.re.match(ngx.ctx.request_header[request_head], request_head_value, "isjo") then
                return true
            end
        end
    end
    return false
end

--匹配参数名和值
function fhgz_diy_rule.ParamPost(option)
    if option == nil or option == "" or option["left_factor"] == "" or option["left_factor"] == nil or option["right_factor"] == "" or option["right_factor"] == nil then return false end
    --正则表达式，不区分大小写
    if ngx.ctx.request_header["content-type"] and ngx.re.find(ngx.ctx.request_header["content-type"], 'multipart', "oij") then return fhgz_diy_rule.ParamFromData(option) end

    ngx.req.read_body()
    local request_args = ngx.req.get_post_args(1000)
    if option["operator"] == "regexp" then
        if ngx.re.match(request_args[option["left_factor"]], option["right_factor"], "isjo") then
            return true
        end
        --匹配开头，不区分大小写
    elseif option["operator"] == "prefix" then
        if ngx.re.match(request_args[option["left_factor"]], "^" .. option["right_factor"], "isjo") then
            return true
        end
        --匹配结尾，不区分大小写
    elseif option["operator"] == "suffix" then
        if ngx.re.match(request_args[option["left_factor"]], option["right_factor"] .. "$", "isjo") then
            return true
        end
        --等于/完全匹配（不区分大小写）
    elseif option["operator"] == "eq" then
        if request_args[option["left_factor"]] == option["right_factor"] then
            return true
        end
        --不等于（不区分大小写）
    elseif option["operator"] == "neq" then
        if request_args[option["left_factor"]] ~= option["right_factor"] then
            return true
        end
        --模糊匹配（不区分大小写）
    elseif option["operator"] == "like" then
        if ngx.re.match(request_args[option["left_factor"]], option["right_factor"], "isjo") then
            return true
        end
    end
    return false
end

--匹配参数名和值
function fhgz_diy_rule.ParamPostBody(option)
    if option == nil or option == "" or option["right_factor"] == "" or option["right_factor"] == nil then return false end
    local content_length = tonumber(ngx.ctx.request_header["content-length"])
    if not content_length then
        return false
    end
    if content_length > 1048576 then
        return false
    end
    ngx.req.read_body()
    local uri = ngx.req.get_body_data()
    --正则表达式，不区分大小写
    if option["operator"] == "regexp" then
        if ngx.re.match(uri, option["right_factor"], "isjo") then
            return true
        end
        --匹配开头，不区分大小写
    elseif option["operator"] == "prefix" then
        if ngx.re.match(uri, "^" .. option["right_factor"], "isjo") then
            return true
        end
        --匹配结尾，不区分大小写
    elseif option["operator"] == "suffix" then
        if ngx.re.match(uri, option["right_factor"] .. "$", "isjo") then
            return true
        end
        --等于/完全匹配（不区分大小写）
    elseif option["operator"] == "eq" then
        if uri == option["right_factor"] then
            return true
        end
        --不等于（不区分大小写）
    elseif option["operator"] == "neq" then
        if uri ~= option["right_factor"] then
            return true
        end
        --模糊匹配（不区分大小写）
    elseif option["operator"] == "like" then
        if ngx.re.match(uri, option["right_factor"], "isjo") then
            return true
        end
        --包含（不区分大小写）
    elseif option["operator"] == "in" then
        local right_factor = Helpers.split(option["right_factor"], ",")
        if right_factor == nil or right_factor == "" then return false end
        for _, v in ipairs(right_factor) do
            if uri == v then
                return true
            end
        end
        --不包含（不区分大小写）
    elseif option["operator"] == "not_in" then
        local right_factor = Helpers.split(option["right_factor"], ",")
        if right_factor == nil or right_factor == "" then return false end
        for _, v in ipairs(right_factor) do
            if uri == v then
                return false
            end
        end
        return true
    end
end

function fhgz_diy_rule.look_for(node)
    if node["option"] == nil then return false end

    --处理各种类型的条件
    local option = node["option"]
    local option_type = option["type"]
    --单ip
    if option_type == "ip" then
        if fhgz_diy_rule.Ip(option) then
            return true
        end

        return false
        --ip段
    elseif option_type == "ip_range" then
        if fhgz_diy_rule.Ip_range(option) then
            return true
        end
        return false
        --ip归属地（地区）
    elseif option_type == "ip_belongs" then
        if fhgz_diy_rule.Ip_area(option) then
            return true
        end
        return false
    elseif option_type == "ip_province" then
        if fhgz_diy_rule.Ip_province(option) then
            return true
        end
        return false
    elseif option_type == "ip_city" then
        if fhgz_diy_rule.Ip_city(option) then
            return true
        end
        return false
        --user-agent
    elseif option_type == "user-agent" then
        if fhgz_diy_rule.User_agent(option) then
            return true
        end
        return false

        --referer 引用方
    elseif option_type == "referer" then
        if fhgz_diy_rule.Referer(option) then
            return true
        end
        return false
        --uri 不带参数
    elseif option_type == "uri" then
        if fhgz_diy_rule.Uri(option) then
            return true
        end
        return false
        --uri 带参数
    elseif option_type == "uri_with_param" then
        if fhgz_diy_rule.Uri(option) then
            return true
        end
        return false
        --uri参数,不带uri
    elseif option_type == "uri_param" then
        if fhgz_diy_rule.Uri(option) then
            return true
        end
        return false
        --请求参数（get+post）匹配名字和值
    elseif option_type == "param" then
        if fhgz_diy_rule.Param(option) then
            return true
        end
        return false
        --请求参数（get+post）只匹配参数名字
    elseif option_type == "param_name" then
        if fhgz_diy_rule.Param_name(option) then
            return true
        end
        return false
        --请求参数 仅get
    elseif option_type == "get_param" then
        if ngx.ctx.method ~= "GET" then return false end
        if fhgz_diy_rule.Param(option) then
            return true
        end
        return false
        --请求参数 仅post
        --请求参数 仅post
    elseif option_type == "post_param" then
        if ngx.ctx.method ~= "POST" then return false end
        if fhgz_diy_rule.ParamPost(option) then
            return true
        end
        return false
    elseif option_type == "body_param" then
        if ngx.ctx.method ~= "POST" then return false end
        if fhgz_diy_rule.ParamPostBody(option) then
            return true
        end
        return false
        --请求参数的数量（get+post）
    elseif option_type == "param_length" then
        if fhgz_diy_rule.Param_count(option) then return true end
        return false
        --请求参数的数量 仅get
    elseif option_type == "get_param_length" then
        if ngx.ctx.method ~= "GET" then return false end
        if fhgz_diy_rule.Param_count(option) then
            return true
        end
        return false
        --请求参数的数量 仅post
    elseif option_type == "post_param_length" then
        if ngx.ctx.method ~= "POST" then return false end
        if fhgz_diy_rule.Param_count(option) then
            return true
        end
        return false
    elseif option_type == "method" then
        if fhgz_diy_rule.Request_method(option) then
            return true
        end
        return false
        --只匹配请求头的名称
    elseif option_type == "request_header_name" then
        if fhgz_diy_rule.Request_header_name(option) then
            return true
        end
        return false
        --匹配请求头的名称和值
    elseif option_type == "request_header" then
        if fhgz_diy_rule.Request_header(option) then
            return true
        end
        return false
        --请求头的数量
    elseif option_type == "request_header_length" then
        if fhgz_diy_rule.Request_header_count(option) then
            return true
        end
        return false
        --其他情况
    else
        return false
    end
end

-- 匹配规则
function fhgz_diy_rule.match_rule(obj)
    local rule_nodes = obj["rule"]
    local data = {}

    for i, node in ipairs(rule_nodes) do
        local is_match = fhgz_diy_rule.look_for(node)
        if node["logic"] == "or" then
            if Helpers.all(data) then
                return true
            end
            data = {}
            table.insert(data, is_match)
        end
        table.insert(data, is_match)
    end

    return Helpers.all(data)
end

function fhgz_diy_rule.check()
    if Helpers.arrlen(SAFEWAF_RULES.waf_diy_rule) == 0 then return false end

    local ip = ngx.ctx.ip
    local uri = ngx.ctx.uri
    for _, v in ipairs(SAFEWAF_RULES.waf_diy_rule) do
        if not v.open then goto continue end
        local name_list = Helpers.split(v.name, ',')
        local is_match_name = Helpers.in_list(ngx.ctx.server_name, name_list)
        if not is_match_name then goto continue end
        local is_match_rule = fhgz_diy_rule.match_rule(v)

        if v.action == "allow" then
            -- 允许通过
            if is_match_rule then
                -- 匹配规则通过，允许通过
                return true
            else
                -- 匹配规则未通过，拒绝通过
                Helpers.logs('放行匹配规则未通过，拒绝通过 ' .. ngx.ctx.ip .. ", " .. ngx.ctx.uri .. " (" .. v.name .. ')')
                Dbs.xlog(GJLX['FHGZ_DIY_RULE'], I18N['FHGZ_DIY_RULE'], I18N['FHGZ_DIY_RULE_MSG'] .. '(' .. v.name .. ')', '')
                Helpers.return_html(403, SAFEWAF_RULES.get_html)
                return false
            end
        elseif v.action == "deny" then
            -- 拒绝通过
            if is_match_rule then
                -- 匹配规则通过，拒绝通过
                Helpers.logs('拒绝匹配规则通过，拒绝通过 ' .. ngx.ctx.ip .. ", " .. ngx.ctx.uri .. " (" .. v.rule_name .. ')')
                if v.action_type == 'black_page' then
                    Dbs.xlog(GJLX['FHGZ_DIY_RULE'], I18N['FHGZ_DIY_RULE'], I18N['FHGZ_DIY_RULE_MSG'] .. '(' .. v.rule_name .. ')', '')
                    Helpers.return_html(403, SAFEWAF_RULES.get_html)
                elseif v.action_type == 'no_response' then
                    ngx.exit(444)
                else
                    ngx.exit(444)
                end
                return false
            else
                -- 匹配规则未通过，允许通过
                return true
            end
        elseif v.action == "validate" then
            -- 验证通过
            if is_match_rule then
                -- 匹配规则通过，人机验证
                Helpers.logs('验证匹配规则通过，人机验证 ' .. ngx.ctx.ip .. ", " .. ngx.ctx.uri .. " (" .. v.rule_name .. ')')
                SAFEWAF_MODS.cc.renjiyanzheng('code')
                return false
            else
                -- 匹配规则未通过，允许通过
                return true
            end
        end

        ::continue::
    end

    return false
end

return fhgz_diy_rule
