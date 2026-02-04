local test = {}

function test.show_log()
    local cjson = require "cjson"
    ngx.log(ngx.ERR, "完整 ctx：\27[92m", cjson.encode(ngx.ctx), "\27[0m")

    local allowed_methods = {
        GET     = true,
        POST    = true,
        PUT     = true,
        DELETE  = true,
        PATCH   = true,
        OPTIONS = true,
        HEAD    = true,
    }
    if not ngx.ctx.uri then
        ngx.log(ngx.ERR, "\27[91m uri 为 nil\27[0m")
        return false
    end

    local headers = ngx.req.get_headers(20000)
    if not headers or headers.host == nil then
        ngx.log(ngx.ERR, "\27[91m host 为 nil\27[0m")
        return false
    end
    Helpers.logs(ngx.req.get_method())
    local method = ngx.req.get_method()
    if allowed_methods[method] then
        local msg = "\n------------------【调试输出开始】-------------------\n\n" ..
            "【local_time】" .. ngx.ctx.local_time .. "\n" ..
            "【local_server_name】" .. ngx.var.server_name .. ":" .. ngx.var.server_port .. "\n" ..
            "【server_name】" .. ngx.ctx.server_name .. "\n" ..
            "【method】" .. method .. "\n" ..
            "【host】" .. headers.host .. "\n" ..
            "【uri】" .. ngx.var.request_uri .. "\n" ..
            "【req】" .. headers.host .. ngx.var.request_uri .. "\n" ..
            "【ip】" .. ngx.ctx.ip .. "\n" ..
            "【ip_en】" .. ngx.ctx.ip_en .. "\n" ..
            "【dazhou】" .. ngx.ctx.ip_dazhou .. "\n" ..
            "【country】" .. ngx.ctx.country .. "\n" ..
            "【ip_province】" .. ngx.ctx.ip_province .. "\n" ..
            "【ip_city】" .. ngx.ctx.ip_city .. "\n" ..
            "【ip_area】" .. ngx.ctx.ip_area .. "\n" ..
            "【ip_isp】" .. ngx.ctx.ip_isp .. "\n" ..
            "\n------------------【调试输出结束】-------------------\n"
        Helpers.logs(msg)
        ngx.log(ngx.ERR, msg)
        -- ngx.log(ngx.ERR, ua_black_test1())
        ngx.log(ngx.ERR, "\n--------------------------------------\n")
    else
        Helpers.logs("不支持的请求方法：" .. method)
        ngx.log(ngx.ERR, "\27[91m不支持的请求方法：" .. method .. "\27[0m")
        ngx.exit(444)
    end
end

function test.debug()
    -- ngx.log(ngx.ERR, ua_black_test1())
    local msg = "\n------------------【DEBUG】-------------------\n\n"
    ngx.log(ngx.ERR, msg)
    -- pcall(Dbs.count_qqcs_add)
    local msg = "\n------------------【DEBUG】-------------------\n\n"
    ngx.log(ngx.ERR, msg)
end

function test.test01()
    local ip = ngx.ctx.ip

    return false
end

return test
