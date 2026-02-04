-- --[[
--     @name ip 相关的库文件
--     @role ip归属地、ip是否被拦截
-- ]] --

local ipinfo = {}


function ipinfo.get_ip_info()
    local client_ip = "unknown"

    -- 从CDN获取客户端ip
    if Config['cdn_sz'] and Config['cdn_sz']['open'] then
        local cdn_sz = Config['cdn_sz']
        local mode = cdn_sz['mode']
        local http_header = cdn_sz['http_header']
        local http_headers = cdn_sz['http_headers']
        local x_forwarded_for = cdn_sz['x_forwarded_for']
        local request_header = ngx.ctx.request_header
        if mode == 1 and http_header ~= '' then
            if request_header[http_header] ~= nil and request_header[http_header] ~= "" then
                client_ip = request_header[http_header]
            end
        elseif mode == 2 and http_headers ~= '' then
            local http_header_list = Helpers.split(http_headers, ',')
            if http_header_list and Helpers.arrlen(http_header_list) >= 1 then
                for _, v in ipairs(http_header_list) do
                    if request_header[v] ~= nil and request_header[v] ~= "" then
                        client_ip = request_header[v]
                        break
                    end
                end
            end
        elseif mode == 3 and request_header.x_forwarded_for ~= nil and x_forwarded_for ~= '' then
            local idx = tonumber(x_forwarded_for)
            local xff_list = Helpers.split(request_header.x_forwarded_for, ',')
            if idx and idx > 0 and xff_list and #xff_list >= idx then
                client_ip = string.match(xff_list[#xff_list - idx + 1]:gsub("%s+", ""), "^.+$")
            end
        end
    end

    if type(client_ip) == 'table' then client_ip = "" end

    if client_ip == 'unknown' then
        client_ip = ngx.var.remote_addr
        if client_ip == nil then
            client_ip = "unknown"
        end
    end

    local ver = Helpers.is_ip_ver(client_ip)
    if ver == "v6" then
        ngx.ctx.ipv6 = 1
    elseif ver == "v4" then
        ngx.ctx.ipv6 = 0
    else
        client_ip = ngx.var.remote_addr
        ngx.ctx.ipv6 = 0
    end
    -- local country, province, city, tag, spider = IpInfo.get_country(client_ip)
    local location = IpDb.getip(client_ip)
    if ver == "v4" then
        ngx.ctx.iplong      = Helpers.c_ip2long(client_ip)
        ngx.ctx.country     = location.guojia
        ngx.ctx.ip_province = location.sheng
        ngx.ctx.ip_city     = location.shi
        ngx.ctx.ip_area     = location.xian
        ngx.ctx.ip_isp      = location.isp
        ngx.ctx.ip_dazhou   = location.dazhou
        ngx.ctx.ip_en       = location.en
        ngx.ctx.ip_lng      = location.lng
        ngx.ctx.ip_lat      = location.lat
    else
        ngx.ctx.iplong = 0
        if country then
            ngx.ctx.country = location.guojia
        else
            ngx.ctx.country = ""
        end
    end
    ngx.ctx.ip = client_ip
end

-- 比较IP是否在IP段内 传入IP段整数数组
function ipinfo.compare_ip2(ips)
    local ip = ngx.ctx.ip
    if ip == 'unknown' then return false end
    if string.find(ip, ':') then return false end
    if ngx.ctx.iplong == 0 then ngx.ctx.iplong = Helpers.ip2long(ip) end
    if type(ips[2]) ~= 'number' and type(ips[1]) ~= 'number' and type(ngx.ctx.iplong) ~= 'number' then return false end
    if ngx.ctx.iplong <= ips[2] and ngx.ctx.iplong >= ips[1] then return true end
    return false
end

--初始化阶段就把所有的蜘蛛IP加载到共享内存中
function ipinfo.load_spider()
    local spider_ips = {}
    local spider_file = { 'baidu', 'google', '_360', 'sogou', 'yahoo', 'bingbot', 'bytespider', 'shenma' }
    -- 蜘蛛的IP段写入到内存中
    for _, file_name in ipairs(spider_file) do
        local data = Helpers.read_file_body(SAFEWAF_INC .. "/spider/" .. file_name .. ".json")
        local ok, zhizhu_list_data = pcall(function() return Json.decode(data) end)
        if ok then
            for _, k in ipairs(zhizhu_list_data) do
                table.insert(spider_ips, k)
            end
        end
    end
    return spider_ips
end

-- 私有辅助函数：将 IPv4 字符串转换为 32 位长整型
-- 仅模块内部使用，不对外暴露
local function ip2long(ip)
    -- 匹配 IPv4 格式，拆分四段数字
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a or not b or not c or not d then
        return nil
    end

    -- 转换为数字并校验范围（0-255）
    a = tonumber(a)
    b = tonumber(b)
    c = tonumber(c)
    d = tonumber(d)
    if not a or not b or not c or not d or
        a < 0 or a > 255 or b < 0 or b > 255 or
        c < 0 or c > 255 or d < 0 or d > 255 then
        return nil
    end

    -- 计算 32 位长整型值
    return a * 2 ^ 24 + b * 2 ^ 16 + c * 2 ^ 8 + d
end

-- 私有辅助函数：将 CIDR 转换为起始/结束 IP 长整型
local function cidr2range(cidr_str)
    -- 拆分 CIDR 地址和掩码位数
    local cidr_ip, mask_bits = cidr_str:match("^([%d%.]+)/(%d+)$")
    if not cidr_ip or not mask_bits then
        return nil, nil
    end

    mask_bits = tonumber(mask_bits)
    if mask_bits < 0 or mask_bits > 32 then
        return nil, nil
    end

    -- 转换 CIDR 基础 IP 为长整型
    local cidr_num = ip2long(cidr_ip)
    if not cidr_num then
        return nil, nil
    end

    -- 计算掩码对应的偏移量（不使用位运算）
    local host_bits = 32 - mask_bits
    local mask_range = 2 ^ host_bits - 1 -- 主机位的最大值
    local start_ip_num = math.floor(cidr_num / (2 ^ host_bits)) * (2 ^ host_bits)
    local end_ip_num = start_ip_num + mask_range

    return start_ip_num, end_ip_num
end

-- 私有辅助函数：将 IP段字符串转换为起始/结束 IP 长整型
local function iprange2range(iprange_str)
    -- 拆分起始 IP 和结束 IP
    local start_ip, end_ip = iprange_str:match("^([%d%.]+)-([%d%.]+)$")
    if not start_ip or not end_ip then
        return nil, nil
    end

    -- 转换为长整型并校验合法性
    local start_num = ip2long(start_ip)
    local end_num = ip2long(end_ip)
    if not start_num or not end_num then
        return nil, nil
    end

    -- 确保起始 IP 小于等于结束 IP（处理用户输入反序的情况）
    if start_num > end_num then
        start_num, end_num = end_num, start_num
    end

    return start_num, end_num
end

-- 对外暴露的核心函数：判断 IP 是否在 单个IP/IP段/CIDR 范围内
-- 参数：
--   ip_str: 待判断的 IP 字符串（如 "192.168.0.50"）
--   range_str: 匹配范围（单个IP/IP段/CIDR，如 "192.168.0.1"、"192.168.0.1-192.168.0.100"、"192.168.0.0/24"）
-- 返回：boolean（true=匹配，false=不匹配/格式非法）
function ipinfo.is_ip_in_range(ip_str, range_str)
    -- 1. 转换目标 IP 为长整型，校验合法性
    local ip_num = ip2long(ip_str)
    if not ip_num then
        return false
    end

    local start_num, end_num
    -- 2. 自动识别范围格式并转换为起始/结束 IP 长整型
    if string.find(range_str, "/") then
        -- 格式1：CIDR（如 192.168.0.0/24）
        start_num, end_num = cidr2range(range_str)
    elseif string.find(range_str, "-") then
        -- 格式2：IP段（如 192.168.0.1-192.168.0.100）
        start_num, end_num = iprange2range(range_str)
    else
        -- 格式3：单个IP（如 192.168.0.1）
        local single_ip_num = ip2long(range_str)
        if not single_ip_num then
            return false -- 单个IP格式不合法
        end
        -- 单个IP的起始和结束都是自身
        start_num, end_num = single_ip_num, single_ip_num
    end

    -- 3. 校验转换结果，判断是否在范围内
    if not start_num or not end_num then
        return false
    end
    return ip_num >= start_num and ip_num <= end_num
end

-- IP检测
function ipinfo.ip_check()
    if SAFEWAF_RULES.load_spider:match(ngx.ctx.ip) then
        return true
    end
    return false
end

-- IP黑名单添加
function ipinfo.ipblack_add(ip, time_out)
    local suo = 'block_ip_' .. ip
    ngx.shared.safewaf:get(suo)
    if ngx.shared.safewaf:get(suo) then return false end

    -- 判断ip是否在白名单中
    if SAFEWAF_MODS.traffic_guard.ip_white(ip) then return false end

    local ip_filter = '/dev/shm/.waf_ip_filter'
    local dony_ip = '+,' .. ip .. ',' .. tostring(time_out)
    Helpers.write_file(ip_filter, dony_ip)
    ngx.shared.safewaf:set(suo, 1, time_out)
end

return ipinfo
