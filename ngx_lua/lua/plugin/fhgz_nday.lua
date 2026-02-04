-- 防护规则 专属规则
local fhgz_nday = {}
local ngx_match = ngx.re.find

function fhgz_nday.check_cms()
    if ngx.ctx.method ~= "POST" then
        return false
    end

    local match_rules = {
        {
            info = "Discuz Getshell",
            uri = "/utility/convert/index.php",
            params = {
                a = "config",
                source = ""
            }
        },
        {
            info = "confluence 远程代码执行",
            uri = "/pages/doenterpagevariables.action",
            params = {
                queryString = ""
            }
        },
        {
            info = "dedecms ad_add.php rce",
            uri = "/ad_add.php",
            params = {
                dopost = "save",
                ["normbody[htmlcode]"] = ""
            }
        },
        {
            info = "dedecms article_string_mix.php rce",
            uri = "/article_string_mix.php",
            params = {
                dopost = "save",
                allsource = ""
            }
        },
        {
            info = "dedecms article_template_rand.php rce",
            uri = "/article_template_rand.php",
            params = {
                dopost = "save",
                templates = ""
            }
        },
        {
            info = "dedecms tpl.php rce",
            uri = "/tpl.php",
            params = {
                filename = "",
                action = "savetagfile",
                content = "",
                token = ""
            }
        },
        {
            info = "泛微OA E-Cology BshServlet rce",
            uri = "/weaver/bsh.servlet.BshServlet",
            params = {
                ["bsh.script"] = "",
                ["bsh.servlet.captureOutErr"] = "",
                ["bsh.servlet.output"] = ""
            }
        },
        {
            {
                info = "帝国CMS rce",
                uri = "/admin/ebak/phome.php",
                params = {
                    mydbname = "",
                    dbchar = "",
                    ["tablename[]"] = ""
                }
            }
        }
    }

    local current_uri = ngx.ctx.uri
    ngx.req.read_body()
    local post_data = ngx.req.get_post_args()
    if not post_data then
        return false
    end

    for _, rule in ipairs(match_rules) do
        -- 仅当URI精确匹配时，才执行参数校验逻辑
        if current_uri == rule.uri then
            local params_match = true
            -- 遍历规则中的参数，校验键/值是否匹配
            for key, expected_val in pairs(rule.params) do
                -- 校验参数键是否存在
                if not post_data[key] then
                    params_match = false
                    break
                end
                -- 预期值非空时，校验值是否完全匹配
                if expected_val ~= "" and post_data[key] ~= expected_val then
                    params_match = false
                    break
                end
            end
            -- URI+参数都匹配则返回true
            if params_match then
                return true
            end
        end
    end

    return false
end

function fhgz_nday.check_wordpress()
    local match_patterns = {
        '/wp-content/plugins/canto/includes/lib/download.php',
        '/wp-content/plugins/media-library-assistant/includes/mla-stream-image.php',
        '/wp-admin/admin-ajax.php',
        '/wp-admin/plugin-editor.php',
        '/wp-json/wp/v2/users',
        '/xmlrpc.php',
        '/wp-admin/update.php',
    }
    local uri = ngx.ctx.uri
    for _, pattern in ipairs(match_patterns) do
        if uri == pattern then
            return true
        end
    end
    return false
end

function fhgz_nday.check_thinkphp()
    -- ThinkPHP_RCE5_0_23
    if ngx.ctx.method == "POST" then
        ngx.req.read_body()
        local data = ngx.req.get_post_args()
        if data == nil then return false end
        if data['_method'] and data['method'] and data['server[REQUEST_METHOD]'] then
            return true
        end
        if data['_method'] and data['method'] and data['server[]'] and data['get[]'] then
            return true
        end
        if type(data['_method']) == 'string' then
            if data['_method'] and ngx_match(data['_method'], 'construct', 'ijo') then
                return true
            end
        end
        if type(data['_method']) == 'table' then
            if not data['_method'] then return false end
            for _, _v2 in pairs(data['_method']) do
                if type(_v2) == 'string' then
                    if ngx_match(_v2, 'construct', 'ijo') then
                        return true
                    end
                end
            end
        end
        return false
    end
    -- ThinkPHP_3_log
    local match_patterns = {
        '^/Application/.+log$',
        '^/Application/.+php$',
        '^/application/.+log$',
        '^/application/.+php$',
        '^/Runtime/.+log$',
        '^/Runtime/.+php$',
        '^/runtime/.+php$',
        '^/runtime/.+log$'
    }
    local uri = ngx.ctx.uri
    for _, pattern in ipairs(match_patterns) do
        if string.find(uri, pattern) then
            return true
        end
    end
    return false
end

function fhgz_nday.check_web()
    if ngx.ctx.method ~= "POST" then
        return false
    end

    local match_rules = {
        {
            info = "jeecg-boot <=3.5.3 远程代码执行",
            uri = "/jeecg-boot/jmreport/loadTableData",
            params = {
                sql = ""
            }
        },
        {
            info = "jeecg-boot 3.0->3.5.3 远程代码执行",
            uri = "/jeecg-boot/jmreport/queryFieldBySql",
            params = {
                sql = ""
            }
        },
        {
            info = "Spring Cloud Gateway 远程代码执行漏洞",
            uri = "/actuator/gateway",
            params = {
                name = "AddResponseHeader",
                id = "",
                args = ""
            }
        },
        {
            info = "ThinkCMF V2 代码执行漏洞",
            uri = "/index.php",
            params = {
                a = "fetch",
                content = ""
            }
        }
    }

    local current_uri = ngx.ctx.uri
    ngx.req.read_body()
    local post_data = ngx.req.get_post_args()
    if not post_data then
        return false
    end

    for _, rule in ipairs(match_rules) do
        -- 仅当URI精确匹配时，才执行参数校验逻辑
        if current_uri == rule.uri then
            local params_match = true
            -- 遍历规则中的参数，校验键/值是否匹配
            for key, expected_val in pairs(rule.params) do
                -- 校验参数键是否存在
                if not post_data[key] then
                    params_match = false
                    break
                end
                -- 预期值非空时，校验值是否完全匹配
                if expected_val ~= "" and post_data[key] ~= expected_val then
                    params_match = false
                    break
                end
            end
            -- URI+参数都匹配则返回true
            if params_match then
                return true
            end
        end
    end

    return false
end

function fhgz_nday.check()
    if Helpers.arrlen(SAFEWAF_RULES.waf_nday) == 0 then return false end
    for __, v in pairs(SAFEWAF_RULES.waf_nday)
    do
        if v.open == true then
            if v.rule_name == "cms" then
                local flag = fhgz_nday.check_cms()
                if flag then
                    Helpers.logs('CMS攻击拦截：' .. ngx.ctx.request_uri .. ' IP：' .. ngx.ctx.ip)
                    Dbs.xlog_time(GJLX['FHGZ_NDAY'], I18N['FHGZ_NDAY'], I18N['FHGZ_NDAY_CMS_MSG'], '', 300)
                    Helpers.return_html(403, SAFEWAF_RULES.get_html)
                    return true
                end
            elseif v.rule_name == "wordpress" then
                local flag = fhgz_nday.check_wordpress()
                if flag then
                    Helpers.logs('WordPress攻击拦截：' .. ngx.ctx.request_uri .. ' IP：' .. ngx.ctx.ip)
                    Dbs.xlog_time(GJLX['FHGZ_NDAY'], I18N['FHGZ_NDAY'], I18N['FHGZ_NDAY_WORDPRESS_MSG'], '', 300)
                    Helpers.return_html(403, SAFEWAF_RULES.get_html)
                    return true
                end
            elseif v.rule_name == "thinkphp" then
                local flag = fhgz_nday.check_thinkphp()
                if flag then
                    Helpers.logs('ThinkPHP攻击拦截：' .. ngx.ctx.request_uri .. ' IP：' .. ngx.ctx.ip)
                    Dbs.xlog_time(GJLX['FHGZ_NDAY'], I18N['FHGZ_NDAY'], I18N['FHGZ_NDAY_THINKPHP_MSG'], '', 300)
                    Helpers.return_html(403, SAFEWAF_RULES.get_html)
                    return true
                end
            elseif v.rule_name == "web" then
                local flag = fhgz_nday.check_web()
                if flag then
                    Helpers.logs('Web攻击拦截：' .. ngx.ctx.request_uri .. ' IP：' .. ngx.ctx.ip)
                    Dbs.xlog_time(GJLX['FHGZ_NDAY'], I18N['FHGZ_NDAY'], I18N['FHGZ_NDAY_WEB_MSG'], '', 300)
                    Helpers.return_html(403, SAFEWAF_RULES.get_html)
                    return true
                end
            end
        end
    end
    return false
end

return fhgz_nday
