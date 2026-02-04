local request_check = {}

-- 记录攻击的详细日志
function request_check.get_intercept_report()
    local data = ""
    data = ngx.ctx.method .. " " .. ngx.unescape_uri(ngx.var.request_uri) .. " " .. "HTTP/1.1\n"
    if not ngx.ctx.request_header then
        return data
    end
    for key, valu in pairs(ngx.ctx.request_header) do
        if type(valu) == "string" then
            data = data .. key .. ": " .. valu .. "\n"
        end
        if type(valu) == "table" then
            for key2, val2 in pairs(valu) do
                data = data .. key .. ": " .. val2 .. "\n"
            end
        end
    end
    data = data .. "AttackerIP: " .. ngx.var.remote_addr .. ":" .. ngx.var.remote_port .. "\n"
    data = data .. "\n"

    if ngx.ctx.method ~= "GET" then
        if ngx.ctx.header_safewaf == true then return data end
        ngx.req.read_body()
        local body_info = ngx.req.get_body_data()
        if body_info then
            if #body_info > 1024 * 1024 and not Config["http_open"] then
                data = data .. string.sub(body_info, 1, 1024 * 1024) .. "\n MAX 1M"
            else
                data = data .. body_info
            end
        else
            if Config["http_open"] then
                local request_args2 = ngx.req.get_body_file()
                request_args2 = Helpers.read_file_body(request_args2)
                if request_args2 ~= nil then data = data .. request_args2 end
            else
                if ngx.ctx.method == "POST" then
                    data = data .. "\n MAX 1M"
                end
            end
            return data
        end
    end
    return data
end

return request_check
