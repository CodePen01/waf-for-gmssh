local city = {}



--自定义拦截全球地区
function city.parse_regions()
    local ip = ngx.ctx.ip
    local area_list = {}
    local area_list_en = {}

    -- 构建数据
    if ngx.ctx.ip_dazhou ~= nil then
        table.insert(area_list, ngx.ctx.ip_dazhou)
        if SAFEWAF_RULES.reg_en[ngx.ctx.ip_dazhou] ~= nil then
            table.insert(area_list_en, SAFEWAF_RULES.reg_en[ngx.ctx.ip_dazhou])
        end
    end
    if ngx.ctx.country ~= nil then
        table.insert(area_list, ngx.ctx.country)
        if SAFEWAF_RULES.reg_en[ngx.ctx.country] ~= nil then
            table.insert(area_list_en, SAFEWAF_RULES.reg_en[ngx.ctx.country])
        end
    end
    if ngx.ctx.ip_province ~= nil then
        table.insert(area_list, ngx.ctx.ip_province)
        if SAFEWAF_RULES.reg_en[ngx.ctx.ip_province] ~= nil then
            table.insert(area_list_en, SAFEWAF_RULES.reg_en[ngx.ctx.ip_province])
        end
    end
    if ngx.ctx.ip_city ~= nil then
        table.insert(area_list, ngx.ctx.ip_city)
        if SAFEWAF_RULES.reg_en[ngx.ctx.ip_city] ~= nil then
            table.insert(area_list_en, SAFEWAF_RULES.reg_en[ngx.ctx.ip_city])
        end
    end
    -- if ngx.ctx.ip_area ~= nil then table.insert(area_list, ngx.ctx.ip_area) end

    if Helpers.count_size(SAFEWAF_RULES.reg_tions_rules) == 0 then return false end
    for _, v in ipairs(SAFEWAF_RULES.reg_tions_rules) do
        if v['open'] ~= nil and v['status'] ~= nil and v['open'] then
            if v["site"][ngx.ctx.server_name] ~= nil then
                if Helpers.count_size(v["region"]) == 0 then goto continue end
                if v["types"] == "refuse" then
                    if v["region"]["海外"] ~= nil then
                        if not Helpers.in_list("中国", area_list) then
                            Helpers.logs("地区限制|" .. "匹配到禁止中国大陆以外的地区访问, IP: " .. ip)
                            Dbs.xlog(GJLX['REG_TIONS'], I18N['REG_TIONS'], I18N['REG_TIONS_MSG'], '')
                            Helpers.return_html(403, SAFEWAF_RULES.city_html)
                        end
                    end
                    if v["region"]["Overseas"] ~= nil then
                        if not Helpers.in_list("CHINA", area_list_en) then
                            Helpers.logs("地区限制|" .. "匹配到禁止中国大陆以外的地区访问, IP: " .. ip)
                            Dbs.xlog(GJLX['REG_TIONS'], I18N['REG_TIONS'], I18N['REG_TIONS_MSG'], '')
                            Helpers.return_html(403, SAFEWAF_RULES.city_html)
                        end
                    end
                    for i, _ in pairs(v["region"]) do
                        if Helpers.in_list(i, area_list) or Helpers.in_list(string.upper(i), area_list_en) then
                            Helpers.logs("地区限制|" .. "匹配到禁止【" .. Helpers.city_join(v["region"]) .. "】访问, IP: " .. ip)
                            Dbs.xlog(GJLX['REG_TIONS'], I18N['REG_TIONS'], I18N['REG_TIONS_MSG'], '')
                            Helpers.return_html(403, SAFEWAF_RULES.city_html)
                        end
                    end
                elseif v["types"] == "accept" then
                    if v["region"]["海外"] ~= nil then
                        if Helpers.in_list("中国", area_list) then
                            Helpers.logs("地区限制|" .. "匹配到只允许【" .. Helpers.city_join(v["region"]) .. "】访问, IP: " .. ip)
                            Dbs.xlog(GJLX['REG_TIONS'], I18N['REG_TIONS'], I18N['REG_TIONS_MSG'], '')
                            Helpers.return_html(403, SAFEWAF_RULES.city_html)
                        end
                    end
                    if v["region"]["Overseas"] ~= nil then
                        if Helpers.in_list("CHINA", area_list_en) then
                            Helpers.logs("地区限制|" .. "匹配到只允许【" .. Helpers.city_join(v["region"]) .. "】访问, IP: " .. ip)
                            Dbs.xlog(GJLX['REG_TIONS'], I18N['REG_TIONS'], I18N['REG_TIONS_MSG'], '')
                            Helpers.return_html(403, SAFEWAF_RULES.city_html)
                        end
                    end
                    for i, _ in pairs(v["region"]) do
                        if not Helpers.in_list(i, area_list) and not Helpers.in_list(string.upper(i), area_list_en) then
                            Helpers.logs("地区限制|" .. "匹配到只允许【" .. Helpers.city_join(v["region"]) .. "】访问, IP: " .. ip)
                            Dbs.xlog(GJLX['REG_TIONS'], I18N['REG_TIONS'], I18N['REG_TIONS_MSG'], '')
                            Helpers.return_html(403, SAFEWAF_RULES.city_html)
                        end
                    end
                end
            end
        end
        ::continue::
    end
end

--自定义拦截国内的城市地区
function city.parse_city()
    local ip = ngx.ctx.ip
    local city = ngx.ctx.ip_city or ""
    local sheng = ngx.ctx.ip_province or ""
    local city_en = SAFEWAF_RULES.reg_en[city] or ""
    local sheng_en = SAFEWAF_RULES.reg_en[sheng] or ""
    if Helpers.count_size(SAFEWAF_RULES.reg_city_rules) == 0 then return false end
    for _, v in ipairs(SAFEWAF_RULES.reg_city_rules) do
        if v['open'] ~= nil and v['status'] ~= nil and v['open'] then
            if v["site"][ngx.ctx.server_name] ~= nil then
                if Helpers.count_size(v["region"]) == 0 then goto continue end
                if v["types"] == "refuse" then
                    if v["region"][city] ~= nil or v["region"][sheng] ~= nil or Helpers.is_area_in_region(city_en, v["region"]) or Helpers.is_area_in_region(sheng_en, v["region"]) then
                        Helpers.logs("省市地区限制|" .. "匹配到禁止【" .. Helpers.city_join(v["region"]) .. "】访问, IP: " .. ip)
                        Dbs.xlog(GJLX['REG_TIONS'], I18N['REG_TIONS'], I18N['REG_TIONS_MSG'], '')
                        Helpers.return_html(403, SAFEWAF_RULES.city_html)
                    end
                elseif v["types"] == "accept" then
                    if v["region"][city] == nil and v["region"][sheng] == nil and not Helpers.is_area_in_region(city_en, v["region"]) and not Helpers.is_area_in_region(sheng_en, v["region"]) then
                        Helpers.logs("省市地区限制|" .. "匹配到只允许【" .. Helpers.city_join(v["region"]) .. "】访问, IP: " .. ip)
                        Dbs.xlog(GJLX['REG_TIONS'], I18N['REG_TIONS'], I18N['REG_TIONS_MSG'], '')
                        Helpers.return_html(403, SAFEWAF_RULES.city_html)
                    end
                end
            end
        end
        ::continue::
    end
end

return city
