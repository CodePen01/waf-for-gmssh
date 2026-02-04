local dbs = {}

function dbs.safewaf_init_db()
    if DB then return false end
    local ok, sqlite3 = pcall(function()
        return require "lsqlite3"
    end)
    if not ok then
        return false
    end
    local path = SAFEWAF_DB .. "/"
    if not Helpers.isdir(path) then Helpers.mkdir(path) end
    if not Helpers.isdir(SAFEWAF_RUN_PATH .. '/db/http_log') then
        Helpers.mkdir(SAFEWAF_RUN_PATH .. '/db/http_log')
        local www_uid = Helpers.getUIDByUsername("www")
        if www_uid == nil then
            Helpers.chown(SAFEWAF_RUN_PATH .. '/db/http_log', 1000, 1000)
        else
            Helpers.chown(SAFEWAF_RUN_PATH .. '/db/http_log', www_uid, www_uid)
        end
    end
    local db_path = path .. "waf_log.db"
    if DB == nil or not DB:isopen() then
        DB = sqlite3.open(db_path)
    end
    if DB == nil then return false end
    local table_name = "waf_log"
    local stmt = DB:prepare("SELECT COUNT(*) FROM sqlite_master where type='table' and name=?")
    local rows = 0
    if stmt ~= nil then
        stmt:bind_values(table_name)
        stmt:step()
        rows = stmt:get_uvalues()
        stmt:finalize()
    end
    if stmt == nil or rows == 0 then
        DB:exec([[PRAGMA synchronous = 0]])
        DB:exec([[PRAGMA page_size = 4096]])
        DB:exec([[PRAGMA journal_mode = wal]])
        DB:exec([[PRAGMA journal_size_limit = 1000000000]])
        DB:exec [[
			CREATE TABLE total_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				time INTEGER,
				time_localtime TEXT,
				server_name TEXT,
				ip TEXT,
				ip_city TEXT,
				ip_country TEXT,
				ip_subdivisions TEXT,
				ip_continent TEXT,
				ip_longitude TEXT,
				ip_latitude TEXT,
				type TEXT,
                url TEXT DEFAULT '',
				uri TEXT,
				user_agent TEXT,
				filter_rule TEXT,
				incoming_value TEXT,
			    value_risk TEXT,
				http_log TEXT,
				http_log_path INTEGER,
				zt INTEGER DEFAULT 1,
				gjlx INTEGER DEFAULT 0,
                remark TEXT DEFAULT '限制访问',
				blockade TEXT DEFAULT '',
				blocking_time INTEGER DEFAULT 0,
				is_status INTEGER DEFAULT 0
			)]]
        DB:exec([[CREATE INDEX id_inx ON total_log(id)]])
        DB:exec([[CREATE INDEX time_inx ON total_log(time)]])
        DB:exec([[CREATE INDEX time_localtime_inx ON total_log(time_localtime)]])
        DB:exec([[CREATE INDEX server_name_inx ON total_log(server_name)]])
        DB:exec([[CREATE INDEX ip_ipx ON total_log(ip)]])
        DB:exec([[CREATE INDEX type_inx ON total_log(type)]])
        DB:exec([[CREATE INDEX filter__inx ON total_log(filter_rule)]])
        DB:exec([[CREATE INDEX ip_country_inx ON total_log(ip_country)]])
    end
end

function dbs.total_log_insert(is_log, server_name, ip, type, uri, user_agent, filter_rule, incoming_value,
                              value_risk, http_log, blockade, blocking_time, remark, gjlx)
    dbs.safewaf_init_db()
    if DB == nil then return false end
    local stmt2 = ""
    if is_log == 'log' then
        stmt2 = DB:prepare [[INSERT INTO total_log(
    		time,time_localtime,server_name,ip, ip_city,ip_country,ip_subdivisions,ip_continent,ip_longitude,ip_latitude,type,url,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path,remark,gjlx)
    		VALUES(:time,:time_localtime,:server_name,:ip,:ip_city,:ip_country,:ip_subdivisions,:ip_continent,:ip_longitude, :ip_latitude,:type,:url,:uri,:user_agent,:filter_rule,:incoming_value,:value_risk,:http_log,:http_log_path,:remark,:gjlx)]]
        if stmt2 == nil then
            Helpers.logs("数据库写入失败 total_log1")
            DB = nil
            return
        end
    elseif is_log == 'ip' then
        stmt2 = DB:prepare [[INSERT INTO total_log(
    		zt,time,time_localtime,server_name,ip, ip_city,ip_country,ip_subdivisions,ip_continent,ip_longitude,ip_latitude,type,url,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path,blockade,blocking_time,is_status,remark,gjlx)
    		VALUES(2,:time,:time_localtime,:server_name,:ip,:ip_city,:ip_country,:ip_subdivisions,:ip_continent,:ip_longitude,:ip_latitude,:type,:url,:uri,:user_agent,:filter_rule,:incoming_value,:value_risk,:http_log,:http_log_path,:blockade,:blocking_time,:is_status,:remark,:gjlx)]]
        if stmt2 == nil then
            Helpers.logs("数据库写入失败2 total_log2")
            DB = nil
            return
        end
    end
    DB:exec([[BEGIN TRANSACTION]])

    local random_token = "SAFE_IS_IMPORTANT"
    if Config['access_token'] ~= nil then
        random_token = Config['access_token']
    end
    local http_log_path = 1
    local http_log_body = ""
    local http_log_body2 = ""
    if ngx.req.get_method() == 'POST' then
        http_log_path = 1
        local date = ngx.localtime():gsub("%-", ""):sub(1, 8)
        Helpers.mkdir(SAFEWAF_RUN_PATH .. '/db/http_log/' .. date)
        http_log_body = SAFEWAF_RUN_PATH .. '/db/http_log/' .. date .. '/' .. ngx.md5(http_log .. random_token) .. '.log'
        http_log_body2 = date .. '/' .. ngx.md5(http_log .. random_token) .. '.log'
    else
        http_log_path = 1
        local date = ngx.localtime():gsub("%-", ""):sub(1, 8)
        Helpers.mkdir(SAFEWAF_RUN_PATH .. '/db/http_log/' .. date)
        http_log_body = SAFEWAF_RUN_PATH .. '/db/http_log/' .. date .. '/' .. ngx.md5(http_log .. random_token) .. '.log'
        http_log_body2 = date .. '/' .. ngx.md5(http_log .. random_token) .. '.log'
    end
    -- 如果 incoming_value 太长了
    if incoming_value ~= nil and #incoming_value > 340 then
        incoming_value = incoming_value:sub(1, 300)
    end
    if user_agent ~= nil and #user_agent > 340 then
        user_agent = user_agent:sub(1, 300)
    end

    local ip_city
    local ip_country
    local ip_province
    local ip_continent
    if Lang == "zh-CN" then
        ip_city = ngx.ctx.ip_city or ""
        ip_country = ngx.ctx.country or ""
        ip_province = ngx.ctx.ip_province or ""
        ip_continent = ngx.ctx.ip_dazhou or ""
    else
        ip_city = SAFEWAF_RULES.reg_en[ngx.ctx.ip_city] or ngx.ctx.ip_city
        ip_country = SAFEWAF_RULES.reg_en[ngx.ctx.country] or ngx.ctx.country
        ip_province = SAFEWAF_RULES.reg_en[ngx.ctx.ip_province] or ngx.ctx.ip_province
        ip_continent = SAFEWAF_RULES.reg_en[ngx.ctx.ip_dazhou] or ngx.ctx.ip_dazhou
    end

    if is_log == 'log' then
        stmt2:bind_names {
            time = os.time(),
            time_localtime = ngx.localtime(),
            server_name = server_name,
            ip = ip,
            ip_city = ip_city,
            ip_country = ip_country,
            ip_subdivisions = ip_province,
            ip_continent = ip_continent,
            ip_longitude = ngx.ctx.ip_lng,
            ip_latitude = ngx.ctx.ip_lat,
            type = type,
            url = server_name .. uri,
            uri = uri,
            user_agent = user_agent,
            filter_rule = filter_rule,
            incoming_value = incoming_value,
            value_risk = value_risk,
            http_log = http_log_body2,
            http_log_path = http_log_path,
            remark = remark,
            gjlx = gjlx,
        }
    elseif is_log == 'ip' then
        stmt2:bind_names {
            time = os.time(),
            time_localtime = ngx.localtime(),
            server_name = server_name,
            ip = ip,
            ip_city = ip_city,
            ip_country = ip_country,
            ip_subdivisions = ip_province,
            ip_continent = ip_continent,
            ip_longitude = ngx.ctx.ip_lng,
            ip_latitude = ngx.ctx.ip_lat,
            type = type,
            url = server_name .. uri,
            uri = uri,
            user_agent = user_agent,
            filter_rule = filter_rule,
            incoming_value = incoming_value,
            value_risk = value_risk,
            http_log = http_log_body2,
            http_log_path = http_log_path,
            blockade = blockade,
            blocking_time = blocking_time,
            is_status = true,
            remark = remark,
            gjlx = gjlx,
        }
    end

    stmt2:step()
    stmt2:reset()
    stmt2:finalize()
    DB:execute([[COMMIT]])
    if http_log_path == 1 then
        local filename = http_log_body
        local fp = io.open(filename, 'wb')
        if fp == nil then return false end
        local logtmp = { http_log }
        local logstr = Json.encode(logtmp)
        fp:write(logstr)
        fp:flush()
        fp:close()
    end
end

function dbs.DbCount_init()
    if DbCount then return false end
    local ok, sqlite3 = pcall(function()
        return require "lsqlite3"
    end)
    if not ok then
        return false
    end
    local path = SAFEWAF_DB .. "/"
    if not Helpers.isdir(path) then Helpers.mkdir(path) end

    local db_path = path .. "count.db"
    if DbCount == nil or not DbCount:isopen() then
        DbCount = sqlite3.open(db_path)
    end
    if DbCount == nil then return false end
    local table_name = "t_qs_log"
    local stmt = DbCount:prepare("SELECT COUNT(*) FROM sqlite_master where type='table' and name=?")
    local rows = 0
    if stmt ~= nil then
        stmt:bind_values(table_name)
        stmt:step()
        rows = stmt:get_uvalues()
        stmt:finalize()
    end
    if stmt == nil or rows == 0 then
        DbCount:exec([[PRAGMA synchronous = 0]])
        DbCount:exec([[PRAGMA page_size = 4096]])
        DbCount:exec([[PRAGMA journal_mode = wal]])
        DbCount:exec([[PRAGMA journal_size_limit = 1000000000]])
        DbCount:exec [[
        CREATE TABLE t_qs_log (id INTEGER  PRIMARY KEY AUTOINCREMENT,
        date VARCHAR (12),
        year INT (4) DEFAULT (0),
        month INT (2) DEFAULT (0),
        day INT (2) DEFAULT (0),
        server_name VARCHAR (64),
        sjlx INT (11) DEFAULT (0),
        qqcs BIGINT DEFAULT (0),
        ljcs BIGINT DEFAULT (0),
        qqll BIGINT DEFAULT (0),
        ljll BIGINT DEFAULT (0)
        )]]
        DbCount:exec([[CREATE INDEX date_index ON t_qs_log(date)]])
        DbCount:exec([[CREATE INDEX year_index ON t_qs_log(year)]])
        DbCount:exec([[CREATE INDEX month_index ON t_qs_log(month)]])
        DbCount:exec([[CREATE INDEX day_index ON t_qs_log(day)]])
        DbCount:exec([[CREATE INDEX server_name_index ON t_qs_log(server_name)]])
        DbCount:exec([[CREATE INDEX sjlx_index ON t_qs_log(sjlx)]])

        DbCount:exec [[
        CREATE TABLE t_req_log (id INTEGER  PRIMARY KEY AUTOINCREMENT,
        time INTEGER,
        time_localtime TEXT,
        date DATE,
        hour INT (3) DEFAULT (0),
        minute INT (3) DEFAULT (0),
        server_name VARCHAR (64),
        lx INT (11) DEFAULT (0),
        ll BIGINT DEFAULT (0)
        )]]
        DbCount:exec([[CREATE INDEX date_index ON t_req_log(date)]])
        DbCount:exec([[CREATE INDEX time_index ON t_req_log(time)]])
        DbCount:exec([[CREATE INDEX hour_index ON t_req_log(hour)]])
        DbCount:exec([[CREATE INDEX minute_index ON t_req_log(minute)]])
        DbCount:exec([[CREATE INDEX server_name_index ON t_req_log(server_name)]])
        DbCount:exec([[CREATE INDEX lx_index ON t_req_log(lx)]])
    end
end

-- 正常请求次数增加
function dbs.count_qqcs_add()
    dbs.DbCount_init()
    if DbCount == nil then return false end

    local server_name = ngx.ctx.server_name
    if server_name == nil or server_name == '' then return false end

    local req_bytes = tonumber(ngx.var.request_length) or 0
    local time = os.time()
    local time_localtime = ngx.localtime()
    local cur_date = os.date("%Y-%m-%d", time)
    local cur_hour = tonumber(os.date("%H"))
    local cur_min = tonumber(os.date("%M"))
    local cur_year = tonumber(os.date("%Y", time))
    local cur_month = tonumber(os.date("%m", time))
    local cur_day = tonumber(os.date("%d", time))
    local date_year = os.date("%Y", time)
    local date_month = os.date("%Y-%m", time)

    local stat_dims = {
        { sjlx = 1,  srv = "",          year = cur_year, month = 0,         day = 0,       date = date_year },
        { sjlx = 2,  srv = "",          year = cur_year, month = cur_month, day = 0,       date = date_month },
        { sjlx = 3,  srv = "",          year = cur_year, month = cur_month, day = cur_day, date = cur_date },
        { sjlx = 11, srv = server_name, year = cur_year, month = 0,         day = 0,       date = date_year },
        { sjlx = 12, srv = server_name, year = cur_year, month = cur_month, day = 0,       date = date_month },
        { sjlx = 13, srv = server_name, year = cur_year, month = cur_month, day = cur_day, date = cur_date }
    }

    DbCount:exec("BEGIN IMMEDIATE TRANSACTION;")

    for _, dim in ipairs(stat_dims) do
        local update_sql = string.format([[
            UPDATE t_qs_log
            SET qqcs = qqcs + 1, qqll = qqll + %d
            WHERE server_name = '%s' AND sjlx = %d AND year = %d AND month = %d AND day = %d
        ]], req_bytes, dim.srv, dim.sjlx, dim.year, dim.month, dim.day)

        DbCount:exec(update_sql)
        local change_rows = DbCount:changes()
        if change_rows == 0 then
            local insert_sql = string.format([[
                INSERT INTO t_qs_log (date, year, month, day, server_name, sjlx, qqcs, ljcs, qqll, ljll)
                VALUES ('%s', %d, %d, %d, '%s', %d, 1, 0, %d, 0)
            ]], dim.date, dim.year, dim.month, dim.day, dim.srv, dim.sjlx, req_bytes)

            DbCount:exec(insert_sql)
        end
    end

    DbCount:exec(string.format(
        [[INSERT INTO t_req_log(time,time_localtime,date,hour,minute,server_name,ll) VALUES (%d,'%s','%s',%d,%d,'%s',%d)]],
        time, time_localtime, cur_date, cur_hour, cur_min, server_name, req_bytes))

    DbCount:exec("COMMIT TRANSACTION;")
end

-- 拦截次数增加
function dbs.count_ljcs_add()
    dbs.DbCount_init()
    if DbCount == nil then return false end


    local server_name = ngx.ctx.server_name
    if server_name == nil or server_name == '' then return false end

    local req_bytes = tonumber(ngx.var.request_length) or 0
    local time = os.time()
    local time_localtime = ngx.localtime()
    local cur_date = os.date("%Y-%m-%d", time)
    local cur_hour = tonumber(os.date("%H"))
    local cur_min = tonumber(os.date("%M"))
    local cur_year = tonumber(os.date("%Y", time))
    local cur_month = tonumber(os.date("%m", time))
    local cur_day = tonumber(os.date("%d", time))
    local date_year = os.date("%Y", time)
    local date_month = os.date("%Y-%m", time)

    local stat_dims = {
        { sjlx = 1,  srv = "",          year = cur_year, month = 0,         day = 0,       date = date_year },
        { sjlx = 2,  srv = "",          year = cur_year, month = cur_month, day = 0,       date = date_month },
        { sjlx = 3,  srv = "",          year = cur_year, month = cur_month, day = cur_day, date = cur_date },
        { sjlx = 11, srv = server_name, year = cur_year, month = 0,         day = 0,       date = date_year },
        { sjlx = 12, srv = server_name, year = cur_year, month = cur_month, day = 0,       date = date_month },
        { sjlx = 13, srv = server_name, year = cur_year, month = cur_month, day = cur_day, date = cur_date }
    }

    DbCount:exec("BEGIN IMMEDIATE TRANSACTION;")

    for _, dim in ipairs(stat_dims) do
        local update_sql = string.format([[
            UPDATE t_qs_log
            SET ljcs = ljcs + 1, ljll = ljll + %d
            WHERE server_name = '%s' AND sjlx = %d AND year = %d AND month = %d AND day = %d
        ]], req_bytes, dim.srv, dim.sjlx, dim.year, dim.month, dim.day)

        DbCount:exec(update_sql)
        local change_rows = DbCount:changes()
        if change_rows == 0 then
            local insert_sql = string.format([[
                INSERT INTO t_qs_log (date, year, month, day, server_name, sjlx, qqcs, ljcs, qqll, ljll)
                VALUES ('%s', %d, %d, %d, '%s', %d, 0, 1, 0, %d)
            ]], dim.date, dim.year, dim.month, dim.day, dim.srv, dim.sjlx, req_bytes)

            DbCount:exec(insert_sql)
        end
    end

    DbCount:exec(string.format(
        [[INSERT INTO t_req_log(time,time_localtime,date,hour,minute,server_name,ll,lx) VALUES (%d,'%s','%s',%d,%d,'%s',%d,1)]],
        time, time_localtime, cur_date, cur_hour, cur_min, server_name, req_bytes))

    DbCount:exec("COMMIT TRANSACTION;")
end

function dbs.xlog(gjlx, lan_type, msg, remark)
    ngx.ctx.xlog_flag = true
    local server_name = ngx.ctx.server_name
    local ip = ngx.ctx.ip
    local method = ngx.ctx.method
    local uri = ngx.unescape_uri(ngx.ctx.request_uri)
    local user_agent = ngx.var.http_user_agent
    local http_logs = SAFEWAF_MODS.request_check.get_intercept_report()
    dbs.total_log_insert('log', server_name, ip, method, uri, user_agent, lan_type, msg, '', http_logs, '', '', remark, gjlx)

    -- 记录拦截次数
    dbs.count_ljcs_add()
    -- 推送告警
    Webhook.ack_dd_webhook(lan_type)
    Webhook.ack_http_webhook(lan_type)
end

function dbs.xlog_time(gjlx, lan_type, msg, remark, drop_time)
    ngx.ctx.xlog_flag = true
    local server_name = ngx.ctx.server_name
    local ip = ngx.ctx.ip
    local method = ngx.ctx.method
    local uri = ngx.unescape_uri(ngx.ctx.request_uri)
    local user_agent = ngx.var.http_user_agent
    local http_logs = SAFEWAF_MODS.request_check.get_intercept_report()
    dbs.total_log_insert('ip', server_name, ip, method, uri, user_agent, lan_type, msg, '', http_logs, lan_type, drop_time, remark, gjlx)

    -- 记录拦截次数
    dbs.count_ljcs_add()
    -- 推送告警
    Webhook.ack_dd_webhook(lan_type)
    Webhook.ack_http_webhook(lan_type)
end

return dbs
