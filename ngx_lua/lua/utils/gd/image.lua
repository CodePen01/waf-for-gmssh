local modulename = "gdImage"
local _M = { _VERSION = '0.0.1', _NAME = modulename }
local mt = {}

local ffi = require('ffi')
local bit = require('bit')
local libgd = require('gd.libgd')
local base = require('gd.base')
local util = require('gd.util')

local ffi_gc = ffi.gc
local bit_band = bit.band

local setmetatable = setmetatable
local tonumber = tonumber
local tostring = tostring
local type = type
local open = io.open
local char = string.char

_M.new = function(self, image)
    if not image then
        return nil, "create failed"
    end

    self.im = ffi_gc(image, libgd.gdImageDestroy)
    return setmetatable(self, mt)
end

_M.free = function(self, str)
    if str then
        libgd.gdFree(str)
        return true
    end
    return false, "str was nil"
end

_M.createPaletteFromTrueColor = function(self, dither, colors)
    colors = tonumber(colors)
    if not colors or colors <= 0 or colors > base.gdMaxColors then
        return nil, "colors must be a number greater than zero and not greater than 256"
    end

    if dither then
        dither = 1
    else
        dither = 0
    end
    local image = self.im
    image = libgd.gdImageCreatePaletteFromTrueColor(image, dither, colors)
    if not image then
        return nil, "create failed"
    end
    return self:new(image)
end

_M.trueColorToPalette = function(self, dither, colors)
    colors = tonumber(colors)
    if not colors or colors <= 0 or colors > base.gdMaxColors then
        return false, "colors must be a number greater than 0 and not greater than 256"
    end

    if dither then
        dither = 1
    else
        dither = 0
    end
    return base.GD_OK == libgd.gdImageTrueColorToPalette(self.im, dither, colors)
end

_M.jpeg = function(self, fname, quality)
    quality = tonumber(quality)
    if not quality or quality < 0 or quality > 100 then
        return false, "quality must be a number between 0 and 100"
    end
    local f, err = open(fname, 'wb')
    if not f then
        return false, err
    end

    libgd.gdImageJpeg(self.im, f, quality)
    if f then
        f:close()
    end
    return true
end

_M.jpegStr = function(self, quality)
    quality = tonumber(quality)
    if not quality or quality < 0 or quality > 100 then
        return nil, "quality must be a number between 0 and 100"
    end

    local blob = libgd.gdImageJpegPtr(self.im, util.get_int_ptr_0(), quality)
    return tostring(blob)
end

_M.png = function(self, fname)
    local f, err = open(fname, 'wb')
    if not f then
        return false, err
    end

    libgd.gdImagePng(self.im, f)
    if f then
        f:close()
    end
    return true
end

_M.pngStr = function(self)
    --获取 gdImagePtr
    local im = self.im

    --分配空间来存储 PNG 数据的大小
    local size = ffi.new("int[1]")

    -- 调用 gdImagePngPtr 获取 PNG 数据及其大小
    local pngData = ffi.C.gdImagePngPtr(im, size)

    -- 检查 pngData 是否为 NULL
    if pngData ~= nil then
        -- 将 C 字符串转换为 Lua 字符串
        local pngStr = ffi.string(pngData, size[0])

        -- 释放 PNG 数据占用的内存
        ffi.C.gdFree(pngData)

        return pngStr
    else
        -- 如果 pngData 为 NULL，返回 nil 表示错误
        return nil
    end
end

_M.pngEx = function(self, fname, compression_level)
    local level = tonumber(compression_level)
    if not level or level < 1 or level > 6 then
        return false, "level must be a number between 1 and 6"
    end
    local f, err = open(fname, 'wb')
    if not f then
        return false, err
    end

    libgd.gdImagePngEx(self.im, f, level)
    if f then
        f:close()
    end
    return true
end

_M.pngStrEx = function(self, compression_level)
    local level = tonumber(compression_level)
    if not level or level < 1 or level > 6 then
        return nil, "level must be a number between 1 and 6"
    end

    local blob = libgd.gdImagePngPtrEx(self.im, util.get_int_ptr_0(), level)
    return tostring(blob)
end

_M.gif = function(self, fname)
    local f, err = open(fname, 'wb')
    if not f then
        return false, err
    end

    libgd.gdImageGif(self.im, f)
    if f then
        f:close()
    end
    return true
end

_M.gifStr = function(self)
    local blob = libgd.gdImageGifPtr(self.im, util.get_int_ptr_0())
    return tostring(blob)
end

_M.gd = function(self, fname)
    local f, err = open(fname, 'wb')
    if not f then
        return false, err
    end

    libgd.gdImageGd(self.im, f)
    if f then
        f:close()
    end
    return true
end

_M.gdStr = function(self)
    local blob = libgd.gdImageGdPtr(self.im, util.get_int_ptr_0())
    return tostring(blob)
end

_M.gd2 = function(self, fname, chunk_size, format)
    chunk_size = tonumber(chunk_size)
    if not chunk_size or chunk_size < 0 then
        return false, "chunk size must be a number greater than 0"
    end

    format = tonumber(format)
    if not format or format ~= base.GD2_FMT_RAW or format ~= base.GD2_FMT_COMPRESSED then
        return false, "format must be gd.GD2_FMT_RAW or gd.GD2_FMT_COMPRESSED"
    end
    local f, err = open(fname, 'wb')
    if not f then
        return false, err
    end

    libgd.gdImageGd2(self.im, f, chunk_size, format)
    if f then
        f:close()
    end
    return true
end

_M.gd2Str = function(self, chunk_size, format)
    chunk_size = tonumber(chunk_size)
    if not chunk_size or chunk_size < 0 then
        return nil, "chunk size must be a number greater than 0"
    end

    format = tonumber(format)
    if not format or format ~= base.GD2_FMT_RAW or format ~= base.GD2_FMT_COMPRESSED then
        return nil, "format must be gd.GD2_FMT_RAW or gd.GD2_FMT_COMPRESSED"
    end

    local blob = libgd.gdImageGd2Ptr(self.im, util.get_int_ptr_0())
    return tostring(blob)
end

_M.wbmp = function(self, foreground, fname)
    local f, err = open(fname, 'wb')
    if not f then
        return false, err
    end

    foreground = tonumber(foreground)
    if not foreground then
        return false, "foreground must be a number"
    end

    libgd.gdImageWBMP(self.im, foreground, f)
    if f then
        f:close()
    end
    return true
end

_M.wbmpStr = function(self, foreground)
    foreground = tonumber(foreground)
    if not foreground then
        return nil, "foreground must be a number"
    end

    local blob = libgd.gdImageWBMPPtr(self.im, util.get_int_ptr_0(), foreground)
    return tostring(blob)
end


_M.webp = function(self, fname)
    local f, err = open(fname, 'wb')
    if not f then
        return false, err
    end

    libgd.gdImageWebp(self.im, f)
    if f then
        f:close()
    end
    return true
end

_M.webpStr = function(self)
    local blob = libgd.gdImageWebpPtr(self.im, util.get_int_ptr_0())
    return tostring(blob)
end

_M.webpEx = function(self, quantization, fname)
    local f, err = open(fname, 'wb')
    if not f then
        return false, err
    end

    quantization = tonumber(quantization)
    if not quantization then
        return false, "quantization must be a number"
    end

    libgd.gdImageWebpEx(self.im, f, quantization)
    if f then
        f:close()
    end
    return true
end

_M.webpExStr = function(self, quantization)
    quantization = tonumber(quantization)
    if not quantization then
        return nil, "quantization must be a number"
    end

    local blob = libgd.gdImageWebpPtrEx(self.im, util.get_int_ptr_0(), quantization)
    return tostring(blob)
end

_M.tiff = function(self, fname)
    local f, err = open(fname, 'wb')
    if not f then
        return false, err
    end

    libgd.gdImageTiff(self.im, f)
    if f then
        f:close()
    end
    return true
end

_M.tiffStr = function(self)
    local blob = libgd.gdImageTiffPtr(self.im, util.get_int_ptr_0())
    return tostring(blob)
end

_M.colorAllocate = function(self, red, green, black)
    red, green, black = tonumber(red), tonumber(green), tonumber(black)
    if not red or not green or not black then
        return nil, "red green black must be a number"
    end
    if red < 0 or green < 0 or black < 0 then
        return nil, "red green black must be a number not less than 0"
    end

    local ret = libgd.gdImageColorAllocate(self.im, red, green, black)
    if ret >= base.GD_OK then
        return ret
    else
        return nil
    end
end

_M.colorAllocateAlpha = function(self, red, green, black, alpha)
    red, green, black = tonumber(red), tonumber(green), tonumber(black)
    alpha = tonumber(alpha)
    if not red or not green or not black then
        return nil, "red green black must be a number"
    end
    if red < 0 or green < 0 or black < 0 then
        return nil, "red green black must be a number not less than 0"
    end
    if not alpha or alpha < 0 then
        return nil, "alpha must be a number not less than 0"
    end

    local ret = libgd.gdImageColorAllocateAlpha(self.im, red, green, black, alpha)
    if ret >= base.GD_OK then
        return ret
    else
        return nil
    end
end

_M.colorClosest = function(self, red, green, black)
    red, green, black = tonumber(red), tonumber(green), tonumber(black)
    if not red or not green or not black then
        return nil, "red green black must be a number"
    end
    if red < 0 or green < 0 or black < 0 then
        return nil, "red green black must be a number not less than 0"
    end

    local ret = libgd.gdImageColorClosest(self.im, red, green, black)
    if ret >= base.GD_OK then
        return ret
    else
        return nil
    end
end

_M.colorClosestAlpha = function(self, red, green, black, alpha)
    red, green, black = tonumber(red), tonumber(green), tonumber(black)
    alpha = tonumber(alpha)
    if not red or not green or not black then
        return nil, "red green black must be a number"
    end
    if red < 0 or green < 0 or black < 0 then
        return nil, "red green black must be a number not less than 0"
    end
    if not alpha or alpha < 0 then
        return nil, "alpha must be a number not less than 0"
    end

    local ret = libgd.gdImageColorClosestAlpha(self.im, red, green, black, alpha)
    if ret >= base.GD_OK then
        return ret
    else
        return nil
    end
end

_M.colorClosestHWB = function(self, red, green, black)
    red, green, black = tonumber(red), tonumber(green), tonumber(black)
    if not red or not green or not black then
        return nil, "red green black must be a number"
    end
    if red < 0 or green < 0 or black < 0 then
        return nil, "red green black must be a number not less than 0"
    end

    local ret = libgd.gdImageColorClosestHWB(self.im, red, green, black)
    if ret >= base.GD_OK then
        return ret
    else
        return nil
    end
end

_M.colorExact = function(self, red, green, black)
    red, green, black = tonumber(red), tonumber(green), tonumber(black)
    if not red or not green or not black then
        return nil, "red green black must be a number"
    end
    if red < 0 or green < 0 or black < 0 then
        return nil, "red green black must be a number not less than 0"
    end

    local ret = libgd.gdImageColorExact(self.im, red, green, black)
    if ret >= base.GD_OK then
        return ret
    else
        return nil
    end
end

_M.colorExactAlpha = function(self, red, green, black, alpha)
    red, green, black = tonumber(red), tonumber(green), tonumber(black)
    alpha = tonumber(alpha)
    if not red or not green or not black then
        return nil, "red green black must be a number"
    end
    if red < 0 or green < 0 or black < 0 then
        return nil, "red green black must be a number not less than 0"
    end
    if not alpha or alpha < 0 then
        return nil, "alpha must be a number not less than 0"
    end

    local ret = libgd.gdImageColorExactAlpha(self.im, red, green, black, alpha)
    if ret >= base.GD_OK then
        return ret
    else
        return nil
    end
end

_M.colorResolve = function(self, red, green, black)
    red, green, black = tonumber(red), tonumber(green), tonumber(black)
    if not red or not green or not black then
        return nil, "red green black must be a number"
    end
    if red < 0 or green < 0 or black < 0 then
        return nil, "red green black must be a number not less than 0"
    end

    local ret = libgd.gdImageColorResolve(self.im, red, green, black)
    if ret >= base.GD_OK then
        return ret
    else
        return nil
    end
end

_M.colorResolveAlpha = function(self, red, green, black, alpha)
    red, green, black = tonumber(red), tonumber(green), tonumber(black)
    alpha = tonumber(alpha)
    if not red or not green or not black then
        return nil, "red green black must be a number"
    end
    if red < 0 or green < 0 or black < 0 then
        return nil, "red green black must be a number not less than 0"
    end
    if not alpha or alpha < 0 then
        return nil, "alpha must be a number not less than 0"
    end

    local ret = libgd.gdImageColorResolveAlpha(self.im, red, green, black, alpha)
    if ret >= base.GD_OK then
        return ret
    else
        return nil
    end
end

_M.colorsTotal = function(self)
    return tonumber(self.im.colorsTotal)
end

_M.red = function(self, color)
    color = tonumber(color)
    if not color and color < 0 then
        return nil, "color must be a number not less than 0"
    end

    return libgd.gdImageRed(self.im, color)
end

_M.blue = function(self, color)
    color = tonumber(color)
    if not color and color < 0 then
        return nil, "color must be a number not less than 0"
    end

    return libgd.gdImageBlue(self.im, color)
end

_M.green = function(self, color)
    color = tonumber(color)
    if not color and color < 0 then
        return nil, "color must be a number not less than 0"
    end

    return libgd.gdImageGreen(self.im, color)
end

_M.alpha = function(self, color)
    color = tonumber(color)
    if not color and color < 0 then
        return nil, "color must be a number not less than 0"
    end

    return libgd.gdImageAlpha(self.im, color)
end

_M.getTransparent = function(self)
    local ret = libgd.gdImageGetTransparent(self.im)
    if ret ~= base.GD_ERR then
        return ret
    else
        return nil
    end
end

_M.colorTransparent = function(self, color)
    color = tonumber(color)
    if not color and color < 0 then
        return false, "color must be a number not less than 0"
    end

    libgd.gdImageColorTransparent(self.im, color)
    return true
end

_M.colorDeallocate = function(self, color)
    color = tonumber(color)
    if not color and color < 0 then
        return false, "color must be a number not less than 0"
    end

    libgd.gdImageColorDeallocate(self.im, color)
    return true
end

_M.boundsSafe = function(self, x, y)
    x, y = tonumber(x), tonumber(y)
    if not x or not y or x < 0 or y < 0 then
        return false, "x y must be a number not less than 0"
    end
    return libgd.gdImageBoundsSafe(self.im, x, y) ~= base.GD_ZERO
end

_M.getPixel = function(self, x, y)
    x, y = tonumber(x), tonumber(y)
    if not x or not y or x < 0 or y < 0 then
        return false, "x y must be a number not less than 0"
    end
    return libgd.gdImageGetPixel(self.im, x, y)
end

_M.setPixel = function(self, x, y, color)
    x, y = tonumber(x), tonumber(y)
    color = tonumber(color)
    if not x or not y or x < 0 or y < 0 then
        return false, "x y must be a number not less than 0"
    end

    libgd.gdImageSetPixel(self.im, x, y, color)
    return true
end

_M.sizeX = function(self)
    return tonumber(self.im.sx)
end

_M.sizeY = function(self)
    return tonumber(self.im.sy)
end

_M.sizeXY = function(self)
    return self:sizeX(), self:sizeY()
end

_M.getClip = function(self)
    local x1, y1 = util.get_int_ptr_0(), util.get_int_ptr_0()
    local x2, y2 = util.get_int_ptr_0(), util.get_int_ptr_0()
    libgd.gdImageGetClip(x1, y1, x2, y2)
    return tonumber(x1), tonumber(y1), tonumber(x2), tonumber(y2)
end

_M.setClip = function(self, x1, y1, x2, y2)
    x1, y1 = tonumber(x1), tonumber(y1)
    x2, y2 = tonumber(x2), tonumber(y2)
    if not x1 or not y1 or not x2 or not y2 then
        return false, "x1 y1 x2 y2 must be a number"
    end

    libgd.gdImageSetClip(self.im, x1, y1, x2, y2)
    return true
end


_M.line = function(self, x1, y1, x2, y2, color)
    x1, y1 = tonumber(x1), tonumber(y1)
    x2, y2 = tonumber(x2), tonumber(y2)
    color = tonumber(color)
    if not x1 or not y1 or not x2 or not y2 or not color then
        return false, "x1 y1 x2 y2 color must be a number"
    end

    libgd.gdImageLine(self.im, x1, y1, x2, y2, color)
    return true
end

_M.rectangle = function(self, x1, y1, x2, y2, color)
    x1, y1 = tonumber(x1), tonumber(y1)
    x2, y2 = tonumber(x2), tonumber(y2)
    color = tonumber(color)
    if not x1 or not y1 or not x2 or not y2 or not color then
        return false, "x1 y1 x2 y2 color must be a number"
    end

    libgd.gdImageRectangle(self.im, x1, y1, x2, y2, color)
    return true
end

_M.filledRectangle = function(self, x1, y1, x2, y2, color)
    x1, y1 = tonumber(x1), tonumber(y1)
    x2, y2 = tonumber(x2), tonumber(y2)
    color = tonumber(color)
    if not x1 or not y1 or not x2 or not y2 or not color then
        return false, "x1 y1 x2 y2 color must be a number"
    end

    libgd.gdImageFilledRectangle(self.im, x1, y1, x2, y2, color)
    return true
end

_M.polygon = function(self, points, color)
    color = tonumber(color)
    if not color or color < 0 then
        return false, "color must be a number not less than 0"
    end

    if not points or type(points) ~= 'table' or #points <= 0 then
        return false, "points must be specified table not empty"
    end

    local plist, err = util.get_point_list(points)
    if not plist then
        return false, err
    end

    libgd.gdImagePolygon(self.im, plist, #points, color)
    plist = nil
    return true
end

_M.filledPolygon = function(self, points, color)
    color = tonumber(color)
    if not color or color < 0 then
        return false, "color must be a number not less than 0"
    end

    if not points or type(points) ~= 'table' or #points <= 0 then
        return false, "points must be specified table not empty"
    end

    local plist, err = util.get_point_list(points)
    if not plist then
        return false, err
    end

    libgd.gdImageFilledPolygon(self.im, plist, #points, color)
    plist = nil
    return true
end

_M.openPolygon = function(self, points, color)
    color = tonumber(color)
    if not color or color < 0 then
        return false, "color must be a number not less than 0"
    end

    if not points or type(points) ~= 'table' or #points <= 0 then
        return false, "points must be specified table not empty"
    end

    local plist, err = util.get_point_list(points)
    if not plist then
        return false, err
    end

    libgd.gdImageOpenPolygon(self.im, plist, #points, color)
    plist = nil
    return true
end

_M.arc = function(self, cx, cy, w, h, s, e, color)
    cx, cy = tonumber(cx), tonumber(cy)
    w, h = tonumber(w), tonumber(h)
    s, e = tonumber(s), tonumber(e)
    color = tonumber(color)
    if not cx or not cy or not w or not h or not s or not e or not color then
        return false, "cx cy w h s e color must be a number"
    end
    if s <= e then
        return false, "s must be greater than e"
    end
    libgd.gdImageArc(self.im, cx, cy, w, h, s, e, color)
    return true
end

_M.filledArc = function(self, cx, cy, w, h, s, e, color, style)
    cx, cy = tonumber(cx), tonumber(cy)
    w, h = tonumber(w), tonumber(h)
    s, e = tonumber(s), tonumber(e)
    color = tonumber(color)
    style = tonumber(style)
    if not cx or not cy or not w or not h or not s or not e or not color or not style then
        return false, "cx cy w h s e color style must be a number"
    end
    if s <= e then
        return false, "s must be greater than e"
    end
    libgd.gdImageFilledArc(self.im, cx, cy, w, h, s, e, color, style)
    return true
end

_M.filledEllipse = function(self, cx, cy, w, h, s, e, color)
    cx, cy = tonumber(cx), tonumber(cy)
    w, h = tonumber(w), tonumber(h)
    s, e = tonumber(s), tonumber(e)
    color = tonumber(color)
    if not cx or not cy or not w or not h or not s or not e or not color then
        return false, "cx cy w h s e color must be a number"
    end
    if s <= e then
        return false, "s must be greater than e"
    end
    libgd.gdImageFilledEllipse(self.im, cx, cy, w, h, s, e, color)
    return true
end

_M.fill = function(self, x, y, color)
    x, y = tonumber(x), tonumber(y)
    color = tonumber(color)
    if not x or not y or x < 0 or y < 0 then
        return false, "x y must be a number not less than 0"
    end
    if not color or color < 0 then
        return false, "color must be a number not less than 0"
    end

    libgd.gdImageFill(self.im, x, y, color)
    return true
end

_M.fillToBorder = function(self, x, y, border, color)
    x, y = tonumber(x), tonumber(y)
    color = tonumber(color)
    border = tonumber(border)
    if not x or not y or x < 0 or y < 0 then
        return false, "x y must be a number not less than 0"
    end
    if not border or not color or border < 0 or color < 0 then
        return false, "boarder color must be a number not less than 0"
    end
    libgd.gdImageFillToBorder(self.im, x, y, border, color)
    return true
end

_M.setAntiAliased = function(self, color)
    color = tonumber(color)
    if not color and color < 0 then
        return false, "color must be a number not less than 0"
    end
    libgd.gdImageSetAntiAliased(self.im, color)
    return true
end

_M.setAntiAliasedDontBlend = function(self, color)
    color = tonumber(color)
    if not color and color < 0 then
        return false, "color must be a number not less than 0"
    end
    libgd.gdImageSetAntiAliasedDontBlend(self.im, color)
    return true
end

_M.setBrush = function(self, brush)
    if not brush then
        return false, "brush not specifed"
    end
    if type(brush) ~= 'cdata' then
        return false, "brush must be cdata<gdImagePtr>"
    end

    libgd.gdImageSetBrush(self.im, brush)
    return true
end

_M.setTile = function(self, tile)
    if not tile then
        return false, "brush not specifed"
    end
    if type(tile) ~= 'cdata' then
        return false, "brush must be cdata<gdImagePtr>"
    end

    libgd.gdImageSetTile(self.im, tile)
    return true
end

_M.setStyle = function(self, styles)
    if not styles or type(styles) ~= 'table' or #styles then
        return false, "styles must be a table"
    end

    local slist = util.get_style_list(styles)
    libgd.gdImageSetStyle(self.im, slist, #styles)
    return true
end

_M.setThickness = function(self, thickness)
    thickness = tonumber(thickness)
    if not thickness then
        return false, "thickness must be a number"
    end
    libgd.gdImageSetThickness(self.im, thickness)
    return true
end

_M.alphaBlending = function(self, blending)
    blending = tonumber(blending)
    if not blending then
        return false, "blending must be a number"
    end
    libgd.gdImageAlphaBlending(self.im, blending)
    return true
end

_M.saveAlpha = function(self, save_or_not)
    local save = 0
    if save_or_not then
        save = 1
    end
    libgd.gdImageSaveAlpha(self.im, save)
end

_M.interlace = function(self)
    local ret = libgd.gdImageGetInterlaced(self.im)
    if ret ~= base.GD_OK then
        return ret
    else
        return nil
    end
end

_M.getInterlaced = _M.interlace

_M.string = function(self, font, x, y, s, color)
    if not font or type(font) ~= 'cdata' then
        return false, "font must be specified as cdata<gdFontPtr>"
    end
    x, y = tonumber(x), tonumber(y)
    if not x or not y or x < 0 or y < 0 then
        return false, "x y must be a number not less than 0"
    end
    color = tonumber(color)
    if not color and color < 0 then
        return false, "color must be a number not less than 0"
    end
    if not s or type(s) ~= 'string' then
        return false, "s must be a string"
    end

    libgd.gdImageString(self.im, font, x, y, util.get_char_ptr(s), color)
    return true
end

_M.stringUp = function(self, font, x, y, s, color)
    if not font or type(font) ~= 'cdata' then
        return false, "font must be specified as cdata<gdFontPtr>"
    end
    x, y = tonumber(x), tonumber(y)
    if not x or not y or x < 0 or y < 0 then
        return false, "x y must be a number not less than 0"
    end
    color = tonumber(color)
    if not color and color < 0 then
        return false, "color must be a number not less than 0"
    end
    if not s or type(s) ~= 'string' then
        return false, "s must be a string"
    end

    libgd.gdImageStringUp(self.im, font, x, y, util.get_char_ptr(s), color)
    return true
end

_M.char = function(self, x, y, c, color)
    x, y = tonumber(x), tonumber(y)
    if not x or not y or x < 0 or y < 0 then
        return false, "x y must be a number not less than 0"
    end
    color = tonumber(color)
    if not color and color < 0 then
        return nil, "color must be a number not less than 0"
    end
    if not c then
        return false, "c must be a char"
    end
    c = char(c) --ascii
    libgd.gdImageChar(self.im, x, y, c, color)
    return true
end

_M.charUp = function(self, x, y, c, color)
    x, y = tonumber(x), tonumber(y)
    if not x or not y or x < 0 or y < 0 then
        return false, "x y must be a number not less than 0"
    end
    color = tonumber(color)
    if not color and color < 0 then
        return false, "color must be a number not less than 0"
    end
    if not c then
        return false, "c must be a char"
    end
    c = char(c) --ascii
    libgd.gdImageCharUp(self.im, x, y, c, color)
    return true
end

_M.squareToCircle = function(self, radius)
    radius = tonumber(radius)
    if not radius then
        return false, "radius must be a number"
    end
    libgd.gdImageSquareToCircle(self.im, radius)
    return true
end

_M.sharpen = function(self, pct)
    pct = tonumber(pct)
    if not pct then
        return false, "pct must be a number"
    end
    libgd.gdImageSharpen(self.im, pct)
    return true
end

_M.stringFT = function(self, foreground, font, size, ang, x, y, str)
    foreground = tonumber(foreground)
    if not foreground then
        return nil, "foreground must be a number"
    end
    if not font or type(font) ~= 'string' then
        return nil, "font must be a string"
    end
    size = tonumber(size)
    if not size then
        return nil, "size must be a number"
    end
    ang = tonumber(ang)
    if not ang then
        return nil, "ang must be a number"
    end
    x, y = tonumber(x), tonumber(y)
    if not x or not y or x < 0 or y < 0 then
        return false, "x y must be a number not less than 0"
    end
    if not str or type(str) ~= 'string' then
        return nil, "str must be a string"
    end

    local brect = util.get_int_ptr_list(8)
    if libgd.gdImageStringFT(self.im, brect, foreground, font, size, ang, x, y, str) == nil then
        return brect[1], brect[2], brect[3], brect[4], brect[5], brect[6], brect[7], brect[8]
    end
    return nil
end

_M.stringFTEx = function(self, foreground, font, size, ang, x, y, str, extr)
    foreground = tonumber(foreground)
    if not foreground then
        return nil, "foreground must be a number"
    end
    if not font or type(font) ~= 'string' then
        return nil, "font must be a string"
    end
    size = tonumber(size)
    if not size then
        return nil, "size must be a number"
    end
    ang = tonumber(ang)
    if not ang then
        return nil, "ang must be a number"
    end
    x, y = tonumber(x), tonumber(y)
    if not x or not y or x < 0 or y < 0 then
        return false, "x y must be a number not less than 0"
    end
    if not str or type(str) ~= 'string' then
        return nil, "str must be a string"
    end
    if not extr or type(extr) ~= 'table' then
        return nil, "extr must be a table"
    end
    local ex = util.get_font_type_extract_ptr(extr)

    local brect = ffi.new("int[8]")
    if libgd.gdImageStringFTEx(self.im, brect, foreground, font, size, ang, x, y, str, ex) == nil then
        -- if bit_band(ex.flags, base.gdFTEX_XSHOW) then
        --     return brect[1], brect[2], brect[3], brect[4], brect[5], brect[6], brect[7], brect[8], ex.xshow
        -- end

        -- if bit_band(ex.flags, base.gdFTEX_RETURNFONTPATHNAME) then
        --     return brect[1], brect[2], brect[3], brect[4], brect[5], brect[6], brect[7], brect[8], ex.xshow, ex.fontpath
        -- end
        -- return brect[1], brect[2], brect[3], brect[4], brect[5], brect[6], brect[7], brect[8]
    end

    return nil
end

_M.stringFTCircle = function(self, x, y, radius, textRadius,
                             fillPortion, fontname, points, top, bottom, color)
    x, y = tonumber(x), tonumber(y)
    if not x or not y then
        return false, "x y must be a number"
    end
    radius, textRadius = tonumber(radius), tonumber(textRadius)
    if not radius or not textRadius then
        return false, "radius textRadius must be a number"
    end
    fillPortion = tonumber(fillPortion)
    if not fillPortion then
        return nil, "fillPortion must be a number"
    end
    if not fontname or type(fontname) ~= 'string' then
        return nil, "fontname must be a string"
    end
    points = tonumber(points)
    if not points then
        return nil, "points must be a number"
    end
    if not top or type(top) ~= 'string' then
        return nil, "top must be a string"
    end
    if not bottom or type(bottom) ~= 'table' then
        return nil, "bottom must be a table"
    end
    color = tonumber(color)
    if not color and color < 0 then
        return false, "color must be a number not less than 0"
    end
    if libgd.gdImageStringFTCircle(self.im, x, y, radius, textRadius,
            fillPortion, fontname, points, top, bottom, color) ~= nil then
        return true
    end
    return false
end

_M.gifAnimBegin = function(self, fname, globalCM, loops)
    local f, err = open(fname, 'wb')
    if not f then
        return false, err
    end
    local global = 0
    if globalCM then
        global = 1
    end
    loops = tonumber(loops)
    if not loops then
        return false, "loops must be a number"
    end
    libgd.gdImageGifAnimBegin(self.im, f, global, loops)
    if f then
        f:close()
    end
    return true
end

_M.gifAnimAdd = function(self, fname, localCM, leftOfs, topOfs, delay,
                         disposal, previm)
    local f, err = open(fname, 'ab')
    if not f then
        return false, err
    end
    local localcm = 0
    if localCM then
        localcm = 1
    end
    leftOfs, topOfs = tonumber(leftOfs), tonumber(topOfs)
    if not leftOfs or not topOfs then
        return false, "leftOfs topOfs must be a number"
    end
    delay = tonumber(delay)
    if not delay then
        return false, "delay must be a number"
    end
    disposal = tonumber(disposal)
    if not disposal then
        return false, "disposal must be a number"
    end

    libgd.gdImageGifAnimAdd(self.im, fname, localCM, leftOfs, topOfs, delay,
        disposal, previm)
    if f then
        f:close()
    end
    return true
end

_M.gifAnimEnd = function(self, fname)
    local f, err = open(fname, 'ab')
    if not f then
        return false, err
    end
    libgd.gdImageGifAnimEnd(f)
    if f then
        f:close()
    end
    return true
end

_M.gifAnimBeginStr = function(self, globalCM, loops)
    local global = 0
    if globalCM then
        global = 1
    end
    loops = tonumber(loops)
    if not loops then
        return nil, "loops must be a number"
    end
    local size = util.get_int_ptr_0()
    return libgd.gdImageGifAnimBeginPtr(self.im, size, global, loops)
end

_M.gifAnimAddStr = function(self, localCM, leftOfs, topOfs, delay,
                            disposal, previm)
    local localcm = 0
    if localCM then
        localcm = 1
    end
    leftOfs, topOfs = tonumber(leftOfs), tonumber(topOfs)
    if not leftOfs or not topOfs then
        return false, "leftOfs topOfs must be a number"
    end
    delay = tonumber(delay)
    if not delay then
        return false, "delay must be a number"
    end
    disposal = tonumber(disposal)
    if not disposal then
        return false, "disposal must be a number"
    end
    local size = util.get_int_ptr_0()
    return libgd.gdImageGifAnimAddPtr(self.im, size, localCM, leftOfs, topOfs, delay,
        disposal, previm)
end

return _M
