-- body 过滤
local body_filter = {}

-- 入口函数
function body_filter.body_safewaf()
    -- 记录正常请求次数
    if ngx.arg[2] then
        Dbs.count_qqcs_add()
    end
    if not Config['open'] or not Helpers.is_site_config('open') then return false end

    SAFEWAF_MODS.conf_mod_mgc_word.body_def_resp_xytm() -- 响应脱敏
    SAFEWAF_MODS.http_check.body_check_404()


    -- WAF END
end

local ok, error = pcall(function()
    return body_filter.body_safewaf()
end)

if not ok then
    if not ngx.shared.safewaf:get("safewaf_body") then
        Helpers.logs(error)
        ngx.shared.safewaf:set("safewaf_body", 1, 300)
    end
end
