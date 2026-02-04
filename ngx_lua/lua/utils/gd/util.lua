local modulename = "gdBase"
local _M = { _NAME = modulename }

local ffi = require('ffi')
local ffi_new = ffi.new
local ffi_copy = ffi.copy

local tonumber = tonumber
local type = type

local int_ptr_0

_M.get_char_ptr = function(str)
    local char_ptr = ffi_new("char[?]", #str)
    ffi_copy(char_ptr, str)
    return char_ptr
end

_M.get_int_ptr_0 = function()
    if not int_ptr_0 then
        int_ptr_0 = ffi_new("int[1]", 0)
    end
    return int_ptr_0
end

_M.get_int_ptr = function(num)
    return ffi_new("int[1]", num)
end

_M.get_int_ptr_list = function(size)
    return ffi_new("int[?]", size)
end

_M.get_point_list = function(points)
    local i = 1
    local size = #points
    local plist = ffi_new("struct gdPointPtr [?]", size)
    while i <= size do
        local point = points[i]
        if not point or type(points) ~= 'table' or #point ~= 2 then
            return nil, "points format could not acceptable"
        end
        local x, y = tonumber(point[1]), tonumber(point[2])
        if not x or not y then
            return nil, "point's x y must be a number"
        end
        local p = ffi_new("struct gdPointPtr")
        p.x, p.y = x, y

        plist[i] = p
        i = i + 1
    end
    return plist
end

_M.get_style_list = function(styles)
    local i = 1
    local size = #styles
    local slist = _M.get_int_ptr_list(size)
    while i <= size do
        local style = tonumber(styles[i])
        if not style then
            return false, "style must be a number"
        end
        slist[i] = style
        i = i + 1
    end
    return slist
end


_M.get_font_type_extract_ptr = function(extr)
    -- Initialize gdFTStringExtra structure
    local ex = ffi.new("gdFTStringExtra")
    ex.flags = 0

    if extr.linespacing then
        ex.flags = ex.flags
        ex.linespacing = tonumber(extr.linespacing)
    end

    return ex
end

return _M
