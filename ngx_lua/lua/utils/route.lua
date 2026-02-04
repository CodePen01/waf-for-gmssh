local route = {}

-- 跳转验证页面
function route.send_tiao_html()
    local ip = ngx.ctx.ip
    local server_name = ngx.ctx.server_name
    local today = ngx.ctx.today
    local token = ''
    local cc_rjyz = 'cc_rjyz'
    if ngx.ctx.ua ~= nil then
        token = ngx.md5(cc_rjyz .. ip .. ngx.ctx.ua .. server_name .. 'tiao' .. today)
    else
        token = ngx.md5(cc_rjyz .. ip .. server_name .. 'tiao' .. today)
    end
    local jwt_value = ngx.md5(os.time() .. ip)
    ngx.shared.safewaf:set(token, jwt_value, 7200)
    ngx.header.Set_Cookie = token .. "=" .. jwt_value .. ';'

    local check_html = [[<html><meta charset="utf-8" /><title></title><div></div></html><script> window.location.href ="]] .. ngx.ctx.request_uri .. [["; </script>]]
    ngx.header.content_type = "text/html;charset=utf8"
    ngx.status = 403
    ngx.say(check_html)
    ngx.exit(403)
end

-- 验证码验证
function route.send_verify_code()
    local body = string.format([[
        <html><head><title>网站防火墙</title><style>.head_title{margin-top:0;font-size:40px;font-weight:lighter}p{font-size:16px;font-weight:lighter;color:#666}.btn{float:left;width:63px;height:40px;background:#148be1;box-shadow:inset 0 1px 2px#148be1;color:#fff;text-shadow:#148be1 0-1px 0;font-size:16px;border:0;cursor:pointer;outline:0;border-top-right-radius:2px;border-bottom-right-radius:2px;transition:all 500ms}.btn:hover{color:#fff;background-color:#148be1;border-color:#148be1}.inp_captcha{float:left;margin-left:10px;padding:10px;width:200px;height:40px;font-size:20px;border-top-left-radius:2px;border-bottom-left-radius:2px;border:1px solid#c0c0c0;outline:0;border-right:0}.inp_captcha:focus{border:1px solid#148be1;border-right:0}.yzm{float:left;width:130px;height:40px;border-radius:2px}.form{margin:0 auto;width:415px;height:40px}</style></head><body><div align="center"style="margin-top:190px"><p style="font-weight: 420;font-size: 20px">人机校验</p><p><font color="red"id="errmsg"></font></p><form class="form"action="#"onsubmit="return false"method="POST"><img class="yzm"id="yzm"onclick="showCaptcha()"alt="验证码图片"><input id="value"class="inp_captcha"name="captcha"type="text"/><button type="submit"class="btn"onclick="mfwaf_auth()"type="button">提交</button></form></div><script>document.onkeydown=function(e){var theEvent=window.event||e;var code=theEvent.keyCode||theEvent.which||theEvent.charCode;if(code==13){var value=document.getElementById("value").value;var c="/wafapi_verify_captcha?captcha="+value;mfajax2("GET",c);theEvent.preventDefault();theEvent.stopPropagation()}};function showCaptcha(){var t=(new Date()).valueOf();var b="/wafapi_get_captcha_base64?captcha="+t;mfajax("GET",b)}showCaptcha();function mfajax(a,b,c){var xmlHttp=new XMLHttpRequest();xmlHttp.onreadystatechange=function(){if(xmlHttp.readyState==4&&xmlHttp.status==200){var data=JSON.parse(xmlHttp.responseText);if(data.status==true){yzm.src="data:image/png;base64,"+data.msg}else{if(data.status){location.href=location.href}else{errmsg.innerHTML="验证码输入错误，请重新输入"}}}else{if(xmlHttp.readyState==4&&xmlHttp.status==404){if(a=="GET"){errmsg.innerHTML="无法获取验证码"}else{errmsg.innerHTML="此IP可能已经被屏蔽，请明天或稍后再试"}}}};xmlHttp.open(a,b,true);xmlHttp.send(c)}function mfajax2(a,b,c){var xmlHttp=new XMLHttpRequest();xmlHttp.onreadystatechange=function(){if(xmlHttp.readyState==4&&xmlHttp.status==200){var data=JSON.parse(xmlHttp.responseText);if(data.status==true){location.href=location.href}else{if(data.status){location.href=location.href}else{errmsg.innerHTML="验证码输入错误，请重新输入"}}}else{if(xmlHttp.readyState==4&&xmlHttp.status==404){if(a=="GET"){errmsg.innerHTML="无法获取验证码"}else{errmsg.innerHTML="此IP可能已经被屏蔽，请明天或稍后再试"}}}};xmlHttp.open(a,b,true);xmlHttp.send(c)}function mfwaf_auth(){var value=document.getElementById("value").value;var c="/wafapi_verify_captcha?captcha="+value;mfajax2("GET",c)};</script></body></html>
	]])
    ngx.header.content_type = "text/html;charset=utf8"
    ngx.status = 403
    ngx.say(body)
    ngx.exit(403)
end

function route.wafapi_get_captcha_base64()
    local ip = ngx.ctx.ip
    math.randomseed(tonumber(tostring(os.time()):reverse():sub(1, 6)))
    local n1 = math.random(1, 50)
    ngx.shared.safewaf:set(ip .. '__captcha', SAFEWAF_RULES.captcha_num2[tostring(n1)], 180)
    local file_name = SAFEWAF_INC .. '/captcha/' .. n1 .. '_' .. SAFEWAF_RULES.captcha_num2[tostring(n1)] .. '.png'
    local data = Helpers.re_png(file_name)
    return Helpers.get_return_state(true, ngx.encode_base64(data))
end

function route.wafapi_verify_captcha()
    local ip = ngx.ctx.ip
    local uri_request_args = ngx.ctx.get_uri_args
    local request_header = ngx.ctx.request_header
    local server_name = ngx.ctx.server_name
    local token = ngx.md5(ip .. 'auth')
    local count, _ = ngx.shared.safewaf:get(token)

    local num2 = ngx.shared.safewaf:get(ip .. '__captcha')
    if num2 == nil then return Helpers.get_return_state(false, '验证码已经过期') end
    if uri_request_args['captcha'] then
        if num2 == string.lower(uri_request_args['captcha']) then
            local token = ''
            local cc_rjyz = 'cc_rjyz'
            if ngx.ctx.ua ~= nil then
                token = ngx.md5(cc_rjyz .. ip .. ngx.ctx.ua .. server_name .. 'code' .. ngx.ctx.today)
            else
                token = ngx.md5(cc_rjyz .. ip .. server_name .. 'code' .. ngx.ctx.today)
            end
            local jwt_value = ngx.md5(os.time() .. ip)
            ngx.shared.safewaf:set(token, jwt_value, 7200)
            ngx.header.Set_Cookie = token .. "=" .. jwt_value .. ';'
            return Helpers.get_return_state(true, '验证成功')
        else
            return Helpers.get_return_state(false, '验证码错误')
        end
    end
    return Helpers.get_return_state(false, '请填写验证码')
end

-- 人机验证
function route.send_verify_renji(type)
    local ip = ngx.ctx.ip
    if type == 'tiao' then
        route.send_tiao_html()
    elseif type == 'code' then
        route.send_verify_code()
    end
end

function route.cc()
    local ip = ngx.ctx.ip
    if not ngx.ctx.url_split then return false end
    if not ngx.ctx.ip then return false end
    local url = ngx.ctx.url_split

    if not url then return false end
    if url == '/wafapi_get_captcha_base64' then
        Helpers.return_message(200, route.wafapi_get_captcha_base64())
    end
    if url == '/wafapi_verify_captcha' then
        Helpers.return_message(200, route.wafapi_verify_captcha())
    end
    -- if url == '/wafapi_get_captcha_base64_test' then
    --     route.send_verify_code()
    -- end
end

return route
