local cc = {}

function cc.renjiyanzheng(type)
    local mod_name = 'cc_rjyz'
    -- 人机验证白名单
    if SAFEWAF_MODS.traffic_guard.renji_white() then return false end

    local token = ''
    local ip = ngx.ctx.ip
    local server_name = ngx.ctx.server_name
    local today = ngx.ctx.today
    if ngx.ctx.ua ~= nil then
        token = ngx.md5(mod_name .. ip .. ngx.ctx.ua .. server_name .. type .. today)
    else
        token = ngx.md5(mod_name .. ip .. server_name .. type .. today)
    end

    local cc_token = ngx.shared.safewaf:get(token)
    if not cc_token or cc_token == nil then
        Helpers.logs('人机黑名单拦截：' .. ngx.ctx.request_uri .. ' IP：' .. ip)
        Route.send_verify_renji(type)
    end
end

return cc
