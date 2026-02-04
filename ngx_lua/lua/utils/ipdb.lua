local ipdb = {}
ipdb.__index = ipdb

-- 工具函数：位左移（替代 <<）
local function lshift(n, bits)
    return n * (2 ^ bits)
end

-- 工具函数：位或（替代 |）
local function bor(a, b, c, d)
    local res = 0
    if a then res = res + a end
    if b then res = res + b end
    if c then res = res + c end
    if d then res = res + d end
    return res
end

-- 构造函数：初始化IP数据库
function ipdb.new()
    local self = setmetatable({}, ipdb)
    -- 【必须修改】替换为你的ip.dat绝对路径
    -- local database_path = "./ip.dat"
    local database_path = SAFEWAF_INC .. "/ip.dat"
    self.fp = io.open(database_path, "rb")
    if not self.fp then
        error("无法打开IP数据库文件: " .. database_path)
    end

    -- 读取文件头16字节
    local buf = self:read(0, 16)
    if #buf ~= 16 then
        error("IP数据库文件头异常，读取字节数不足")
    end

    -- 解析文件头参数（BytesToLong）
    self.firstStartIpOffset = self:BytesToLong(
        buf:sub(1, 1), buf:sub(2, 2), buf:sub(3, 3), buf:sub(4, 4)
    )
    self.prefixStartOffset = self:BytesToLong(
        buf:sub(9, 9), buf:sub(10, 10), buf:sub(11, 11), buf:sub(12, 12)
    )
    self.prefixEndOffset = self:BytesToLong(
        buf:sub(13, 13), buf:sub(14, 14), buf:sub(15, 15), buf:sub(16, 16)
    )
    self.prefixCount = math.floor((self.prefixEndOffset - self.prefixStartOffset) / 9) + 1

    -- 加载前缀索引表（核心修复：数字键 + 严格偏移）
    self.prefix_array = {}
    local pref_buf = self:read(self.prefixStartOffset, self.prefixCount * 9)
    if #pref_buf ~= self.prefixCount * 9 then
        error("前缀索引数据读取异常")
    end
    for k = 0, self.prefixCount - 1 do
        local i = k * 9                                -- 完全$k*9
        -- Lua字符串索引从1开始，所以所有偏移+1
        local prefix_byte = pref_buf:sub(i + 1, i + 1) -- $pref_buf[$i]
        local prefix = string.byte(prefix_byte)        -- ord($pref_buf[$i])

        -- 解析start_index（$pref_buf[1+$i] 到 $pref_buf[4+$i]）
        local start_index = self:BytesToLong(
            pref_buf:sub(i + 2, i + 2),
            pref_buf:sub(i + 3, i + 3),
            pref_buf:sub(i + 4, i + 4),
            pref_buf:sub(i + 5, i + 5)
        )
        -- 解析end_index（$pref_buf[5+$i] 到 $pref_buf[8+$i]）
        local end_index = self:BytesToLong(
            pref_buf:sub(i + 6, i + 6),
            pref_buf:sub(i + 7, i + 7),
            pref_buf:sub(i + 8, i + 8),
            pref_buf:sub(i + 9, i + 9)
        )
        -- 数字键存储（关键！是数字索引）
        self.prefix_array[prefix] = {
            start_index = start_index,
            end_index = end_index
        }
    end

    return self
end

-- 严格read函数
function ipdb:read(offset, numberOfBytes)
    if not self.fp then return "" end
    self.fp:seek("set", offset)
    local data = self.fp:read(numberOfBytes)
    return data or ""
end

-- 1:1复刻的BytesToLong函数（无任何运算符）
function ipdb:BytesToLong(a, b, c, d)
    local ord_a = string.byte(a or "\0")
    local ord_b = string.byte(b or "\0")
    local ord_c = string.byte(c or "\0")
    local ord_d = string.byte(d or "\0")

    -- 纯函数实现 (ord($a) << 0) | (ord($b) << 8) | (ord($c) << 16) | (ord($d) << 24)
    local part1 = lshift(ord_a, 0)
    local part2 = lshift(ord_b, 8)
    local part3 = lshift(ord_c, 16)
    local part4 = lshift(ord_d, 24)
    local iplong = bor(part1, part2, part3, part4)

    -- 严格负数补偿
    if iplong < 0 then
        iplong = iplong + 4294967296
    end
    return iplong
end

-- 1:1复刻的ip2uint（ip2long + 负数补偿）
function ipdb:ip2uint(strIP)
    local parts = {}
    for part in strIP:gmatch("%d+") do
        table.insert(parts, tonumber(part))
    end
    if #parts ~= 4 then return 0 end
    local a, b, c, d = parts[1], parts[2], parts[3], parts[4]

    -- 完全复刻的ip2long逻辑
    local lngIP = (a * 256 + b) * 256 + c
    lngIP = lngIP * 256 + d
    --  ip2long返回有符号整数，模拟溢出
    if lngIP > 2147483647 then
        lngIP = lngIP - 4294967296
    end
    -- 负数补偿
    if lngIP < 0 then
        lngIP = lngIP + 4294967296
    end
    return lngIP
end

-- 严格BinarySearch
function ipdb:BinarySearch(low, high, k)
    local M = 0
    while low <= high do
        local mid = math.floor((low + high) / 2)
        local endipNum = self:GetEndIp(mid)
        if endipNum >= k then
            M = mid
            if mid == 0 then
                break
            end
            high = mid - 1
        else
            low = mid + 1
        end
    end
    return M
end

-- 严格GetIndex
function ipdb:GetIndex(left)
    local left_offset = self.firstStartIpOffset + (left * 12)
    local buf = self:read(left_offset, 12)
    if #buf ~= 12 then
        return { startip = 0, endip = 0, local_offset = 0, local_length = 0 }
    end

    local startip = self:BytesToLong(buf:sub(1, 1), buf:sub(2, 2), buf:sub(3, 3), buf:sub(4, 4))
    local endip = self:BytesToLong(buf:sub(5, 5), buf:sub(6, 6), buf:sub(7, 7), buf:sub(8, 8))

    -- 复刻的r3计算：(ord($buf[8]) << 0 | ord($buf[9]) << 8 | ord($buf[10]) << 16)
    local ord8 = string.byte(buf:sub(9, 9))
    local ord9 = string.byte(buf:sub(10, 10))
    local ord10 = string.byte(buf:sub(11, 11))
    local r3 = bor(lshift(ord8, 0), lshift(ord9, 8), lshift(ord10, 16))
    if r3 < 0 then
        r3 = r3 + 4294967296
    end

    return {
        startip = startip,
        endip = endip,
        local_offset = r3,
        local_length = string.byte(buf:sub(12, 12))
    }
end

-- 严格getEndIp
function ipdb:GetEndIp(left)
    local left_offset = self.firstStartIpOffset + (left * 12) + 4
    local buf = self:read(left_offset, 4)
    if #buf ~= 4 then return 0 end
    return self:BytesToLong(buf:sub(1, 1), buf:sub(2, 2), buf:sub(3, 3), buf:sub(4, 4))
end

-- 严格GetLocal
function ipdb:GetLocal(local_offset, local_length)
    return self:read(local_offset, local_length)
end

-- 核心查询函数（1:1复刻）
function ipdb:get(ip_address)
    if ip_address == "" then
        return ""
    end

    local high = 0
    local low = 0
    local ipNum = self:ip2uint(ip_address)

    -- 解析前缀（数字类型，explode('.',$ip)[0]）
    local prefix = tonumber(ip_address:match("^(%d+)%.")) or 0

    -- 前缀匹配（数字键，关键！）
    if not self.prefix_array[prefix] then
        return ""
    end
    local index = self.prefix_array[prefix]
    low = index.start_index
    high = index.end_index

    -- 二分查找
    local left = (low == high) and low or self:BinarySearch(low, high, ipNum)

    -- 获取索引信息
    local index_info = self:GetIndex(left)

    -- 验证IP范围
    if index_info.startip <= ipNum and index_info.endip >= ipNum then
        return self:GetLocal(index_info.local_offset, index_info.local_length)
    else
        return ""
    end
end

-- 关闭文件
function ipdb:close()
    if self.fp then
        self.fp:close()
        self.fp = nil
    end
end

-- 修复空白字符的拆分逻辑（1:1explode+list）
function ipdb:split_location(location_str)
    -- 第一步：清理所有空白字符（空格、制表符、换行符）
    local clean_str = string.gsub(location_str, "%s+", "") -- 移除所有空白

    -- 第二步：复刻的explode("|", $str)（关键：保留空字段）
    local parts = {}
    local start = 1
    -- 遍历字符串，按|拆分，即使字段为空也保留
    while start <= #clean_str do
        local pos = string.find(clean_str, "|", start, true)
        if pos then
            table.insert(parts, string.sub(clean_str, start, pos - 1))
            start = pos + 1
        else
            table.insert(parts, string.sub(clean_str, start))
            break
        end
    end

    -- 第三步：list变量顺序，不足11个字段补空，多余字段截断
    local fields = {
        "dazhou",   -- 1: 大洲
        "guojia",   -- 2: 国家
        "sheng",    -- 3: 省
        "shi",      -- 4: 市
        "xian",     -- 5: 县
        "isp",      -- 6: 运营商
        "areacode", -- 7: 区号
        "en",       -- 8: 英文
        "cc",       -- 9: 国家码
        "lng",      -- 10: 经度
        "lat"       -- 11: 纬度
    }

    local result = {}
    for i, field_name in ipairs(fields) do
        result[field_name] = parts[i] or "" -- 空字段填充为空字符串
    end

    return result
end

function ipdb.getip(target_ip)
    local ip_db = ipdb.new()
    local result = ip_db:get(target_ip)
    local location = {};

    if result and result ~= "" then
        location = ip_db:split_location(result)
    else
        location = {
            dazhou = "",   -- 1: 大洲
            guojia = "",   -- 2: 国家
            sheng = "",    -- 3: 省
            shi = "",      -- 4: 市
            xian = "",     -- 5: 县
            isp = "",      -- 6: 运营商
            areacode = "", -- 7: 区号
            en = "",       -- 8: 英文
            cc = "",       -- 9: 国家码
            lng = "",      -- 10: 经度
            lat = ""       -- 11: 纬度
        }
    end
    ip_db:close()
    return location
end

return ipdb
