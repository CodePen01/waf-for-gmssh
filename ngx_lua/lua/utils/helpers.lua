local helpers = {}
local ffi = require("ffi")

-- cffi相关函数开始
ffi.cdef [[
    typedef struct DIR DIR;
    struct dirent {
        uint64_t      d_ino;
        int64_t       d_off;
        unsigned short d_reclen;
        unsigned char  d_type;
        char           d_name[];
    };


    DIR *opendir(const char *name);
    struct dirent *readdir(DIR *dirp);
    int closedir(DIR *dirp);
    int mkdir(const char *path, int mode);

    typedef unsigned int uid_t;
    typedef unsigned int gid_t;

    int chown(const char *path, uid_t owner, gid_t group);
	int access(const char *pathname, int mode);

    struct passwd {
        char *pw_name;
        char *pw_passwd;
        uid_t pw_uid;
        gid_t pw_gid;
        // 其他字段省略，可以根据实际需要添加
    };
    struct passwd *getpwnam(const char *name);

    typedef long time_t;
    typedef struct timeval {
        time_t tv_sec;
        time_t tv_usec;
    } timeval;

    typedef struct in6_addr {
        union {
            uint8_t u6_addr8[16];
            uint16_t u6_addr16[8];
            uint32_t u6_addr32[4];
        } in6_u;
    } in6_addr;

    typedef struct in_addr {
        uint32_t s_addr;
    }in_addr;

    int inet_pton(int af, const char *src, void *dst);

    int gettimeofday(struct timeval *tv, void *tz);

    uint32_t ntohl(uint32_t netlong);
]]


-- 设置文件或目录的所有者和组
function helpers.chown(path, owner, group)
    local result = ffi.C.chown(path, owner, group)
    if result == 0 then
        return true
    else
        return false
    end
end

-- 根据用户名获取用户的UID
function helpers.getUIDByUsername(username)
    local passwdStruct = ffi.C.getpwnam(username)
    if passwdStruct ~= nil then
        local uid = tonumber(passwdStruct.pw_uid)
        return uid
    else
        return nil
    end
end

-- 新建目录
function helpers.mkdir(path)
    local result = ffi.C.mkdir(path, tonumber("755", 8)) -- 755权限，表示读写执行权限
    if result == 0 then
        return true
    else
        return false
    end
end

--获取文件夹下的所有文件
function helpers.isdir(path)
    local dir_list = {}
    -- Open a directory
    local dir = ffi.C.opendir(path)
    if dir == nil then
        return false
    end
    ffi.C.closedir(dir)
    return true
end

--获取文件夹下的所有文件
function helpers.listdir(path)
    local dir_list = {}
    local dir = ffi.C.opendir(path)
    if dir == nil then
        return dir_list
    end
    local entry = ffi.C.readdir(dir)
    while entry ~= nil do
        local entryName = ffi.string(entry.d_name)
        if entryName ~= "." and entryName ~= ".." then
            table.insert(dir_list, entryName)
        end
        entry = ffi.C.readdir(dir)
    end
    ffi.C.closedir(dir)
    return dir_list
end

-- 追加文件内容
function helpers.append_file(filename, body)
    local fp = io.open(filename, "a+")
    if fp == nil then
        return nil
    end
    fp:write(body)
    fp:flush()
    fp:close()
    return true
end

-- 日志写入
-- @param ... 内容
-- @return true or false
function helpers.logs(...)
    local data = "[" .. os.date("%Y-%m-%d %H:%M:%S") .. "]"
    for _, v in ipairs({ ... }) do
        if type(v) == "table" then -- 如果是table，尝试格式化输出
            Json.encode_sparse_array(true, 1)
            data = data .. "\n" .. tostring(v) .. ": \n" .. helpers.PrintTable(v)
        else
            data = data .. " " .. tostring(v)
        end
    end
    local log_file = "/www/server/safewaf/log/safewaf_debug.log"
    helpers.append_file(log_file, data .. "\n")
end

--ip转为整数
function helpers.ip2long(ip)
    local num = 0
    if ip and type(ip) == "string" then
        local o1, o2, o3, o4 = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
        if o1 == nil or o2 == nil or o3 == nil or o4 == nil then
            return 0
        end
        num = 2 ^ 24 * o1 + 2 ^ 16 * o2 + 2 ^ 8 * o3 + o4
    end
    return num
end

function helpers.c_ip2long(ip)
    local ipv4_addr = ffi.new("in_addr")
    local result = ffi.C.inet_pton(2, ip, ipv4_addr) -- 2 代表 AF_INET (IPv4)
    if result == 1 then
        return ffi.C.ntohl(ipv4_addr.s_addr)         -- 使用 ntohl 函数转换字节序
    else
        return 0
    end
end

-- 整数转为IP
function helpers.long2ip(long)
    local floorList = {}
    local yushu = long
    for i = 3, 0, -1 do
        local res = math.floor(yushu / (256 ^ i))
        table.insert(floorList, tonumber(res))
        yushu = yushu - res * 256 ^ i
    end
    return table.concat(floorList, ".")
end

-- 返回json格式数据
function helpers.return_message(status, msg)
    ngx.header.content_type = "application/json;"
    ngx.status = status
    ngx.say(Json.encode(msg))
    ngx.exit(status)
end

-- 返回html格式数据
function helpers.return_html(status, html)
    ngx.header.content_type = "text/html"
    ngx.status = status
    ngx.say(html)
    ngx.exit(status)
end

--统一返回格式
function helpers.get_return_state(status, msg)
    local result = {}
    result["status"] = status
    result["msg"] = msg
    return result
end

function helpers.read_file_body(filename)
    if filename == nil then return nil end
    local fp = io.open(filename, 'r')
    if fp == nil then
        return nil
    end
    local fbody = fp:read("*a")
    fp:close()
    if fbody == '' then
        return nil
    end
    return fbody
end

function helpers.read_file(name)
    local fbody = helpers.read_file_body(SAFEWAF_RUN_PATH .. "/exc/" .. name .. '.json')
    if fbody == nil then
        return {}
    end
    --判断Json格式是否正确
    local status, result = pcall(Json.decode, fbody)
    if status then
        return result
    end
    return {}
end

function helpers.re_png(filename)
    local fp = io.open(filename, 'rb')
    if fp == nil then
        return nil
    end
    local fbody = fp:read("*a")
    fp:close()
    if fbody == '' then
        return nil
    end
    return fbody
end

function helpers.write_file(filename, body)
    local fp = io.open(filename, 'w')
    if fp == nil then
        return nil
    end
    fp:write(body)
    fp:flush()
    fp:close()
    return true
end

-- 搜索字符串
function helpers.find_str(str, find_str)
    if not str or not find_str then
        return false
    end
    local s, e = string.find(str, find_str, 1, true)
    if s and e then
        return true
    end
    return false
end

-- 验证是否为IPV4的地址
function helpers.is_ipv4(ip)
    local pattern = "^(%d+)%.(%d+)%.(%d+)%.(%d+)$"
    local a, b, c, d = ip:match(pattern)
    if not (a and b and c and d) then
        return false
    end
    if tonumber(a) > 255 or tonumber(b) > 255 or tonumber(c) > 255 or tonumber(d) > 255 then
        return false
    end
    return true
end

--验证是否为IPV6的地址
function helpers.is_ipv6(ip)
    local ipv6_addr = ffi.new("in6_addr")
    local result = ffi.C.inet_pton(10, ip, ipv6_addr)
    return result == 1
end

-- 验证是否为IPV4的地址
function helpers.is_in_addr_ipv4(ip)
    local ipv4_addr = ffi.new("in_addr")
    local result = ffi.C.inet_pton(2, ip, ipv4_addr)
    return result == 1
end

--判断是否为IP格式
function helpers.is_ip_ver(ip)
    if helpers.is_in_addr_ipv4(ip) then
        return "v4"
    end
    if helpers.is_ipv6(ip) then
        return "v6"
    end
    return "no"
end

-- 字符串分割
function helpers.split(string, reps)
    if string == nil or string == "" or reps == nil then
        return nil
    end
    local result = {}
    for match in (string .. reps):gmatch("(.-)" .. reps) do
        table.insert(result, match)
    end
    return result
end

function helpers.url_split(url)
    if not url or type(url) ~= "string" then return {} end
    local result = {}
    local special_chars = { ["'"] = true, ['"'] = true, ["<"] = true, [">"] = true, ["%"] = true, ["."] = true, [";"] = true }
    local start = 2 -- 跳过第一个'/'
    local len = #url
    local i = start
    local temp = ""
    local found_special = false

    while i <= len do
        local c = url:sub(i, i)
        if not found_special then
            if c == "/" then
                if #temp > 0 then
                    table.insert(result, temp)
                    temp = ""
                end
            elseif special_chars[c] then
                found_special = true
                temp = url:sub(i)
                table.insert(result, temp)
                break
            else
                temp = temp .. c
            end
        else
            temp = temp .. c
        end
        i = i + 1
    end
    if not found_special and #temp > 0 then
        table.insert(result, temp)
    end
    return result
end

-- 模拟Python的in关键字：纯精准匹配，不去除空格
-- @param elem 要查找的元素
-- @param list 待检查的列表（table）
-- @return 存在返回true，否则返回false
function helpers.in_list(elem, list)
    if not list or not elem then
        return false
    end
    for _, v in ipairs(list) do
        if v == elem then
            return true
        end
    end
    return false
end

-- 取ngx.var.request_uri 不带参数的值
function helpers.get_request_uri()
    --返回的是字符串
    local uri = ngx.var.request_uri
    if uri == ngx.ctx.uri then return ngx.var.request_uri end
    if uri == nil then return "/" end
    uri = uri:gsub('//+', '/')
    if uri == ngx.var.uri then return uri end
    --通过byte
    for i = 1, #uri do
        local byte = uri:byte(i)
        if byte == 63 then
            return uri:sub(1, i - 1)
        end
    end
    return uri
end

function helpers.get_server_name()
    local c_name = ngx.var.server_name .. ":" .. ngx.var.server_port
    local my_name = ngx.shared.safewaf:get(c_name)

    if my_name then
        if my_name == '127.0.0.1' then return c_name end
        return my_name
    end

    local tmp = helpers.read_file_body(SAFEWAF_RUN_PATH .. '/domains.json')
    if not tmp then return c_name end
    local domains = Json.decode(tmp)
    for _, v in ipairs(domains)
    do
        for _, d_name in ipairs(v['domains'])
        do
            if c_name == d_name then
                ngx.shared.safewaf:set(c_name, v['name'], 3600)
                return v['name']
            end
        end
    end

    local headers = ngx.req.get_headers(20000)
    local headers_host = ''
    if not headers or headers.host == nil then
        headers_host = '未绑定域名'
    else
        headers_host = headers.host
    end
    local ret_name = headers_host .. ":" .. ngx.var.server_port
    ngx.shared.safewaf:set(c_name, ret_name, 3600)
    return ret_name
end

function helpers.arrlen(arr)
    if not arr then return 0 end
    local count = 0
    for _, v in pairs(arr)
    do
        count = count + 1
    end
    return count
end

function helpers.count_size(data)
    local count = 0
    if type(data) ~= "table" then return count end
    for _, v in pairs(data)
    do
        count = count + 1
    end
    return count
end

function helpers.is_site_config(cname)
    if Site_config[ngx.ctx.server_name] ~= nil then
        return Site_config[ngx.ctx.server_name][cname]
    end
    return true
end

function helpers.get_mod_conf(cname)
    local conf = Config[cname]
    local mode = helpers.is_site_config('mode')
    if not conf == nil then return false end
    if not mode == nil then return false end
    if mode == 2 then
        conf = Helpers.is_site_config(cname)
    end
    return conf
end

--获取表长度
--@param data 表
--@return 长度
function helpers.len(data)
    local count = 0
    if type(data) ~= "table" then
        return count
    end
    for k, v in pairs(data) do
        count = count + 1
    end
    return count
end

function helpers.return_404()
    local html_data = helpers.read_file_body(SAFEWAF_RUN_PATH .. "/html/" .. Lang .. "/404.html")
    return html_data
end

-- 所有规则都需要匹配
function helpers.all(data)
    for _, v in ipairs(data) do
        if v == false then
            return false
        end
    end
    return true
end

-- 任意规则匹配
function helpers.any(data)
    for _, v in ipairs(data) do
        if v == true then
            return true
        end
    end
    return false
end

-- 检查是否为静态文件
function helpers.check_static()
    local keys = { "css", "js", "png", "gif", "ico", "jpg", "jpeg", "bmp", "flush", "swf", "pdf", "rar", "zip", "doc", "docx", "xlsx", "webp" }
    for _, k in ipairs(keys)
    do
        local aa = "/?.*\\." .. k .. "$"
        if ngx.re.find(ngx.ctx.uri, aa, "isjo") then
            return true
        end
    end
    return false
end

function helpers.check_rebot()
    if not ngx.var.http_user_agent then return true end
    local aa =
    ".*(selenium|requests|python|java|php|ruby|go|c#|.net|perl|javascript|jquery|ajax|curl|wget|httpclient|python-requests|go-http-client|java-http-client|php-http-client|ruby-http-client|c#-http-client|perl-http-client|javascript-http-client|jquery-http-client|ajax-http-client|curl-http-client|wget-http-client|python-requests-http-client|go-http-client-http-client|java-http-client-http-client|php-http-client-http-client|ruby-http-client-http-client|c#-http-client-http-client|perl-http-client-http-client|javascript-http-client-http-client|jquery-http-client-http-client|ajax-http-client-http-client|curl-http-client-http-client|wget-http-client-http-client).*"
    if ngx.re.find(ngx.var.http_user_agent, aa, "isjo") then
        return true
    end
    return false
end

-- 检查城市名（忽略大小写）是否在region数组中
function helpers.is_area_in_region(area, region)
    if area == nil or region == nil then return false end
    if area == "" then return false end
    local target = string.upper(area)
    for i, _ in pairs(region) do
        if string.upper(i) == target then
            return true
        end
    end
    return false
end

function helpers.city_join(reg)
    if type(reg) ~= 'table' then
        return ''
    end
    local info = ""
    local count = 0
    for i, _ in pairs(reg)
    do
        if count > 0 then
            i = "," .. i
        end
        count = count + 1
        info = info .. i
    end
    return info
end

function helpers.load_modules()
    for _, filename in pairs(helpers.listdir(SAFEWAF_MODULE_PATH)) do
        local mod_name = string.match(filename, "(.*)%.lua")
        if SAFEWAF_MODS[mod_name] == nil then
            SAFEWAF_MODS[mod_name] = {}
            SAFEWAF_MODS[mod_name] = require(mod_name)
        end
    end
end

return helpers
