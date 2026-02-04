-- 护网模式 过滤
local hw_mode = {}

function hw_mode.check()
    if not Config['hw_mode'] == nil then return false end
    if not Config['hw_mode'] then return false end

    --不允许非GET请求
    if ngx.ctx.method ~= "GET" then
        Helpers.logs('护网模式拦截, 不允许出现GET以外的请求' .. ' IP：' .. ngx.ctx.ip)
        Dbs.xlog(GJLX['HW_MODE'], I18N['HW_MODE'], I18N['HW_MODE_MSG_NO_GET'], '')
        Helpers.return_html(403, SAFEWAF_RULES.get_html)
    end
    if Helpers.len(ngx.ctx.get_uri_args) == 0 then return false end
    --get参数不能大于10
    if Helpers.len(ngx.ctx.get_uri_args) >= 10 then
        Helpers.logs('护网模式拦截, 不允许get参数大于10' .. ' IP：' .. ngx.ctx.ip)
        Dbs.xlog(GJLX['HW_MODE'], I18N['HW_MODE'], I18N['HW_MODE_MSG_NO_GET_DY10'], '')
        Helpers.return_html(403, SAFEWAF_RULES.get_html)
    end
    --判断参数内容是否符合规则  参数内容只允许是数字和字母
    for k, v in pairs(ngx.ctx.get_uri_args) do
        --只允许是数字和字母
        if type(v) == "string" and #v > 50 then
            Helpers.logs('护网模式拦截, 参数内容不能大于50' .. ' IP：' .. ngx.ctx.ip)
            Dbs.xlog(GJLX['HW_MODE'], I18N['HW_MODE'], I18N['HW_MODE_MSG_NO_ARGS_DY50'], '')
            Helpers.return_html(403, SAFEWAF_RULES.get_html)
        end
        if type(v) == "string" and #v > 5 and not ngx.re.match(v, "^[A-Za-z0-9_\\-\\+\\* ]+$") then
            Helpers.logs('护网模式拦截, 参数内容只允许是数字和字母' .. ' IP：' .. ngx.ctx.ip)
            Dbs.xlog(GJLX['HW_MODE'], I18N['HW_MODE'], I18N['HW_MODE_MSG_ARGS_ONLY_ZNSZ'], '')
            Helpers.return_html(403, SAFEWAF_RULES.get_html)
        end
    end
    --header头部信息总的不能大于20
    if Helpers.len(ngx.ctx.request_header) >= 20 then
        Helpers.logs('护网模式拦截, header长度不能大于20' .. ' IP：' .. ngx.ctx.ip)
        Dbs.xlog(GJLX['HW_MODE'], I18N['HW_MODE'], I18N['HW_MODE_MSG_NO_HEADER_DY20'], '')
        Helpers.return_html(403, SAFEWAF_RULES.get_html)
    end
    --ua长度不能小于5 大于200
    if string.len(ngx.ctx.ua) <= 5 or string.len(ngx.ctx.ua) >= 200 then
        Helpers.logs('护网模式拦截, ua长度不能大于200' .. ' IP：' .. ngx.ctx.ip)
        Dbs.xlog(GJLX['HW_MODE'], I18N['HW_MODE'], I18N['HW_MODE_MSG_NO_UA_DY200'], '')
        Helpers.return_html(403, SAFEWAF_RULES.get_html)
    end
    --Cookie 总长度不能大于500
    if Helpers.len(ngx.var.http_cookie) >= 500 then
        Helpers.logs('护网模式拦截, cookie长度不允许大于500' .. ' IP：' .. ngx.ctx.ip)
        Dbs.xlog(GJLX['HW_MODE'], I18N['HW_MODE'], I18N['HW_MODE_MSG_NO_COOKIE_DY500'], '')
        Helpers.return_html(403, SAFEWAF_RULES.get_html)
    end
    --其他的头部长度不能超过300
    for _, v in ipairs(ngx.ctx.request_header) do
        --判断头部的长度是否超过300
        if #v >= 300 then
            Helpers.logs('护网模式拦截, header头部不允许大于300' .. ' IP：' .. ngx.ctx.ip)
            Dbs.xlog(GJLX['HW_MODE'], I18N['HW_MODE'], I18N['HW_MODE_MSG_NO_HEADER_DY300'], '')
            Helpers.return_html(403, SAFEWAF_RULES.get_html)
        end
    end
end

return hw_mode
