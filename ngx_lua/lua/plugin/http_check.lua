local http_check = {}

function http_check.check_404()
    if not Config['open'] or not Helpers.is_site_config('open') then return false end
    if ngx.status == 404 then
        Helpers.logs('[body_filter] 404 IP: ' .. ngx.var.remote_addr .. ' uri: ' .. ngx.var.request_uri)
        Dbs.xlog(GJLX['ERROR_404'], I18N['ERROR_404'], I18N['ERROR_404_MSG'], '')
        Helpers.return_html(404, SAFEWAF_RULES.error_404)
    end
end

function http_check.body_check_404()
    if not Config['open'] or not Helpers.is_site_config('open') then return false end
    if ngx.status == 404 and not ngx.ctx.xlog_flag then
        local is_last_chunk = ngx.arg[2] -- 核心标记，必须保留
        if is_last_chunk then
            Helpers.logs('[body_filter2] 404 IP: ' .. ngx.var.remote_addr .. ' uri: ' .. ngx.var.request_uri)
            Dbs.xlog(GJLX['ERROR_404'], I18N['ERROR_404'], I18N['ERROR_404_MSG'], '')
            ngx.arg[1] = Helpers.return_404()
            ngx.arg[2] = true;
        else
            ngx.arg[1] = ""
        end
    end
end

return http_check
