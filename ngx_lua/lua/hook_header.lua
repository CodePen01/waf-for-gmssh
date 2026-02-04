-- header 过滤
local header_filter = {}


local ok, error = pcall(function()
    if not Config['open'] or not Helpers.is_site_config('open') then return false end
    if ngx.status == 404 and not ngx.ctx.xlog_flag then
        local html_404               = Helpers.return_404()
        ngx.header["Content-Length"] = #html_404 -- #取字节数，保证与实际响应体完全一致
    end
end)

if not ok then
    if not ngx.shared.safewaf:get("safewaf_header") then
        Helpers.logs(error)
        ngx.shared.safewaf:set("safewaf_header", 1, 300)
    end
end
