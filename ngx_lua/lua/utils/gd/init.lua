local modulename = "gdInit"
local _M = { _NAME = modulename }

local libgd = require('gd.libgd')
local base = require('gd.base')
local util = require('gd.util')
local image = require('gd.image')
local bit = require('bit')

local tonumber = tonumber
local type = type
local len = string.len
local open = io.open
local bit_band = bit.band

_M.destroy = function(image)
    if image and image.im then
        image.im = nil
        image = nil
        return true
    end
    return false
end

_M.create = function(sx, sy)
    sx, sy = tonumber(sx), tonumber(sy)
    if not sx or not sy or sx <= 0 or sy <= 0 then
        return nil, "sx and sy must be a number greater than 0"
    end
    local im = libgd.gdImageCreate(sx, sy)
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createPalette = _M.create

_M.createTrueColor = function(sx, sy)
    sx, sy = tonumber(sx), tonumber(sy)
    if not sx or not sy or sx <= 0 or sy <= 0 then
        return nil, "sx and sy must be a number greater than 0"
    end
    local im = libgd.gdImageCreateTrueColor(sx, sy)
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromJpeg = function(fname)
    local file, err = open(fname, "rb")
    if not file then
        return nil, err
    end
    local im = libgd.gdImageCreateFromJpeg(file)
    if file then
        file:close()
    end
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromJpegStr = function(blob)
    if not blob or type(blob) ~= 'string' or len(blob) <= 0 then
        return nil, "blob could not accept"
    end
    local data = util.get_char_ptr(blob)
    local im = libgd.gdImageCreateFromJpegPtr(len(blob), data)
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromGif = function(fname)
    local file, err = open(fname, "rb")
    if not file then
        return nil, err
    end
    local im = libgd.gdImageCreateFromGif(file)
    if file then
        file:close()
    end
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromGifStr = function(blob)
    if not blob or type(blob) ~= 'string' or len(blob) <= 0 then
        return nil, "blob could not accept"
    end
    local data = util.get_char_ptr(blob)
    local im = libgd.gdImageCreateFromGifPtr(len(blob), data)
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromPng = function(fname)
    local file, err = open(fname, "rb")
    if not file then
        return nil, err
    end
    local im = libgd.gdImageCreateFromPng(file)
    if file then
        file:close()
    end
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromPngStr = function(blob)
    if not blob or type(blob) ~= 'string' or len(blob) <= 0 then
        return nil, "blob could not accept"
    end
    local data = util.get_char_ptr(blob)
    local im = libgd.gdImageCreateFromPngPtr(len(blob), data)
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromGd = function(fname)
    local file, err = open(fname, "rb")
    if not file then
        return nil, err
    end
    local im = libgd.gdImageCreateFromGd(file)
    if file then
        file:close()
    end
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromGdStr = function(blob)
    if not blob or type(blob) ~= 'string' or len(blob) <= 0 then
        return nil, "blob could not accept"
    end
    local data = util.get_char_ptr(blob)
    local im = libgd.gdImageCreateFromGdPtr(len(blob), data)
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromGd2 = function(fname)
    local file, err = open(fname, "rb")
    if not file then
        return nil, err
    end
    local im = libgd.gdImageCreateFromGd2(file)
    if file then
        file:close()
    end
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromGd2Str = function(blob)
    if not blob or type(blob) ~= 'string' or len(blob) <= 0 then
        return nil, "blob could not accept"
    end
    local data = util.get_char_ptr(blob)
    local im = libgd.gdImageCreateFromGd2Ptr(len(blob), data)
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromGd2Part = function(fname, sx, sy, w, h)
    sx, sy, w, h = tonumber(sx), tonumber(sy), tonumber(w), tonumber(h)
    if not sx or not sy or sx < 0 or sy < 0 then
        return nil, "sx and sy must be a number not less than 0"
    end
    if not w or not h or w < 0 or h < 0 then
        return nil, "w and h must be a number not less than 0"
    end

    local file, err = open(fname, "rb")
    if not file then
        return nil, err
    end
    local im = libgd.gdImageCreateFromGd2Part(file, sx, sy, w, h)
    if file then
        file:close()
    end
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromGd2PartStr = function(blob, sx, sy, w, h)
    sx, sy, w, h = tonumber(sx), tonumber(sy), tonumber(w), tonumber(h)
    if not sx or not sy or sx < 0 or sy < 0 then
        return nil, "sx and sy must be a number not less than 0"
    end
    if not w or not h or w < 0 or h < 0 then
        return nil, "w and h must be a number not less than 0"
    end

    if not blob or type(blob) ~= 'string' or len(blob) <= 0 then
        return nil, "blob could not accept"
    end
    local data = util.get_char_ptr(blob)
    local im = libgd.gdImageCreateFromGd2PartPtr(len(blob), data)
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromXbm = function(fname)
    local file, err = open(fname, "rb")
    if not file then
        return nil, err
    end
    local im = libgd.gdImageCreateFromXbm(file)
    if file then
        file:close()
    end
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromXpm = function(fname)
    if not fname then
        return nil, "fname must not be empty"
    end
    local im = libgd.gdImageCreateFromXpm(util.get_char_ptr(fname))
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromWebp = function(fname)
    local file, err = open(fname, "rb")
    if not file then
        return nil, err
    end
    local im = libgd.gdImageCreateFromWebp(file)
    if file then
        file:close()
    end
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromWebpStr = function(blob)
    if not blob or type(blob) ~= 'string' or len(blob) <= 0 then
        return nil, "blob could not accept"
    end
    local data = util.get_char_ptr(blob)
    local im = libgd.gdImageCreateFromWebpPtr(len(blob), data)
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromTiff = function(fname)
    local file, err = open(fname, "rb")
    if not file then
        return nil, err
    end
    local im = libgd.gdImageCreateFromTiff(file)
    if file then
        file:close()
    end
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.createFromTiffStr = function(blob)
    if not blob or type(blob) ~= 'string' or len(blob) <= 0 then
        return nil, "blob could not accept"
    end
    local data = util.get_char_ptr(blob)
    local im = libgd.gdImageCreateFromTiffPtr(len(blob), data)
    if im == nil then
        return nil, "create failed"
    end
    return image:new(im)
end

_M.png = function(im, fname)
    if not im or type(im) ~= 'cdata' then
        return false, "im must be specified as cdata<gdImagePtr>"
    end

    local gd = image:new(im)
    return gd:png(fname)
end

_M.pngEx = function(im, fname, compression_level)
    if not im or type(im) ~= 'cdata' then
        return false, "im must be specified as cdata<gdImagePtr>"
    end

    local gd = image:new(im)
    return gd:pngEx(fname, compression_level)
end

_M.gif = function(im, fname)
    if not im or type(im) ~= 'cdata' then
        return false, "im must be specified as cdata<gdImagePtr>"
    end

    local gd = image:new(im)
    return gd:gif(fname)
end

_M.gd = function(im, fname)
    if not im or type(im) ~= 'cdata' then
        return false, "im must be specified as cdata<gdImagePtr>"
    end

    local gd = image:new(im)
    return gd:gd(fname)
end

_M.gd2 = function(im, fname, chunk_size, format)
    if not im or type(im) ~= 'cdata' then
        return false, "im must be specified as cdata<gdImagePtr>"
    end

    local gd = image:new(im)
    return gd:gd2(fname, chunk_size, format)
end

_M.wbmp = function(im, foreground, fname)
    if not im or type(im) ~= 'cdata' then
        return false, "im must be specified as cdata<gdImagePtr>"
    end

    local gd = image:new(im)
    return gd:wbmp(foreground, fname)
end

_M.copy = function(dst, src, dx, dy, sx, sy, w, h)
    if not dst or not src or type(dst) ~= 'cdata' or type(src) ~= 'cdata' then
        return false, "dst src must be specified as cdata<gdImagePtr>"
    end

    dx, dy = tonumber(dx), tonumber(dy)
    if not dx or not dy or dx < 0 or dy < 0 then
        return false, "dx and dy must be a number not less than 0"
    end
    sx, sy = tonumber(sx), tonumber(sy)
    if not sx or not sy or sx < 0 or sy < 0 then
        return false, "sx and sy must be a number not less than 0"
    end
    w, h = tonumber(w), tonumber(h)
    if not w or not h or w < 0 or h < 0 then
        return false, "w and h must be a number not less than 0"
    end
    libgd.gdImageCopy(dst, src, dx, dy, sx, sy, w, h)
    return true
end

_M.copyResized = function(dst, src, dx, dy, sx, sy, dw, dh, sw, sh)
    if not dst or not src or type(dst) ~= 'cdata' or type(src) ~= 'cdata' then
        return false, "dst src must be specified as cdata<gdImagePtr>"
    end

    dx, dy = tonumber(dx), tonumber(dy)
    if not dx or not dy or dx < 0 or dy < 0 then
        return false, "dx and dy must be a number not less than 0"
    end
    sx, sy = tonumber(sx), tonumber(sy)
    if not sx or not sy or sx < 0 or sy < 0 then
        return false, "sx and sy must be a number not less than 0"
    end
    dw, dh = tonumber(dw), tonumber(dh)
    if not dw or not dh or dw < 0 or dh < 0 then
        return false, "dw and dh must be a number not less than 0"
    end
    sw, sh = tonumber(sw), tonumber(sh)
    if not sw or not sh or sw < 0 or sh < 0 then
        return false, "sw and sh must be a number not less than 0"
    end

    libgd.gdImageCopyResized(dst, src, dx, dy, sx, sy, dw, dh, sw, sh)
    return true
end

_M.copyResampled = function(dst, src, dx, dy, sx, sy, dw, dh, sw, sh)
    if not dst or not src or type(dst) ~= 'cdata' or type(src) ~= 'cdata' then
        return false, "dst src must be specified as cdata<gdImagePtr>"
    end

    dx, dy = tonumber(dx), tonumber(dy)
    if not dx or not dy or dx < 0 or dy < 0 then
        return false, "dx and dy must be a number not less than 0"
    end
    sx, sy = tonumber(sx), tonumber(sy)
    if not sx or not sy or sx < 0 or sy < 0 then
        return false, "sx and sy must be a number not less than 0"
    end
    dw, dh = tonumber(dw), tonumber(dh)
    if not dw or not dh or dw < 0 or dh < 0 then
        return false, "dw and dh must be a number not less than 0"
    end
    sw, sh = tonumber(sw), tonumber(sh)
    if not sw or not sh or sw < 0 or sh < 0 then
        return false, "sw and sh must be a number not less than 0"
    end

    libgd.gdImageCopyResampled(dst, src, dx, dy, sx, sy, dw, dh, sw, sh)
    return true
end

_M.copyRotated = function(dst, src, dx, dy, sx, sy, dw, dh, sw, sh, angle)
    if not dst or not src or type(dst) ~= 'cdata' or type(src) ~= 'cdata' then
        return false, "dst src must be specified as cdata<gdImagePtr>"
    end

    dx, dy = tonumber(dx), tonumber(dy)
    if not dx or not dy or dx < 0 or dy < 0 then
        return false, "dx and dy must be a number not less than 0"
    end
    sx, sy = tonumber(sx), tonumber(sy)
    if not sx or not sy or sx < 0 or sy < 0 then
        return false, "sx and sy must be a number not less than 0"
    end
    dw, dh = tonumber(dw), tonumber(dh)
    if not dw or not dh or dw < 0 or dh < 0 then
        return false, "dw and dh must be a number not less than 0"
    end
    sw, sh = tonumber(sw), tonumber(sh)
    if not sw or not sh or sw < 0 or sh < 0 then
        return false, "sw and sh must be a number not less than 0"
    end
    angle = tonumber(angle)
    if not angle then
        return false, "angle must be a number"
    end

    libgd.gdImageCopyRotated(dst, src, dx, dy, sx, sy, dw, dh, sw, sh, angle)
    return true
end

_M.copyMerge = function(dst, src, dx, dy, sx, sy, dw, dh, sw, sh, pct)
    if not dst or not src or type(dst) ~= 'cdata' or type(src) ~= 'cdata' then
        return false, "dst src must be specified as cdata<gdImagePtr>"
    end

    dx, dy = tonumber(dx), tonumber(dy)
    if not dx or not dy or dx < 0 or dy < 0 then
        return false, "dx and dy must be a number not less than 0"
    end
    sx, sy = tonumber(sx), tonumber(sy)
    if not sx or not sy or sx < 0 or sy < 0 then
        return false, "sx and sy must be a number not less than 0"
    end
    dw, dh = tonumber(dw), tonumber(dh)
    if not dw or not dh or dw < 0 or dh < 0 then
        return false, "dw and dh must be a number not less than 0"
    end
    sw, sh = tonumber(sw), tonumber(sh)
    if not sw or not sh or sw < 0 or sh < 0 then
        return false, "sw and sh must be a number not less than 0"
    end
    pct = tonumber(pct)
    if not pct then
        return false, "pct must be a number"
    end

    libgd.gdImageCopyMerge(dst, src, dx, dy, sx, sy, dw, dh, sw, sh, pct)
    return true
end

_M.copyMergeGray = function(dst, src, dx, dy, sx, sy, dw, dh, sw, sh, pct)
    if not dst or not src or type(dst) ~= 'cdata' or type(src) ~= 'cdata' then
        return false, "dst src must be specified as cdata<gdImagePtr>"
    end

    dx, dy = tonumber(dx), tonumber(dy)
    if not dx or not dy or dx < 0 or dy < 0 then
        return false, "dx and dy must be a number not less than 0"
    end
    sx, sy = tonumber(sx), tonumber(sy)
    if not sx or not sy or sx < 0 or sy < 0 then
        return false, "sx and sy must be a number not less than 0"
    end
    dw, dh = tonumber(dw), tonumber(dh)
    if not dw or not dh or dw < 0 or dh < 0 then
        return false, "dw and dh must be a number not less than 0"
    end
    sw, sh = tonumber(sw), tonumber(sh)
    if not sw or not sh or sw < 0 or sh < 0 then
        return false, "sw and sh must be a number not less than 0"
    end
    pct = tonumber(pct)
    if not pct then
        return false, "pct must be a number"
    end

    libgd.gdImageCopyMergeGray(dst, src, dx, dy, sx, sy, dw, dh, sw, sh, pct)
    return true
end

_M.polygon = function(im, points, color)
    if not im or type(im) ~= 'cdata' then
        return false, "im must be specified as cdata<gdImagePtr>"
    end
    color = tonumber(color)
    if not color then
        return false, "color must be a number not less than 0"
    end

    if not points or type(points) ~= 'table' or #points <= 0 then
        return false, "points must be specified table not empty"
    end

    local plist, err = util.get_point_list(points)
    if not plist then
        return false, err
    end

    libgd.gdImagePolygon(im, plist, #points, color)
    plist = nil
    return true
end

_M.filledPolygon = function(im, points, color)
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

    libgd.gdImageFilledPolygon(im, plist, #points, color)
    plist = nil
    return true
end

_M.openPolygon = function(im, points, color)
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

    libgd.gdImageOpenPolygon(im, plist, #points, color)
    plist = nil
    return true
end

_M.setStyle = function(im, styles)
    if not styles or type(styles) ~= 'table' or #styles then
        return false, "styles must be a table"
    end

    local slist = util.get_style_list(styles)
    libgd.gdImageSetStyle(im, slist, #styles)
    return true
end

_M.alphaBlending = function(im, blending)
    blending = tonumber(blending)
    if not blending then
        return false, "blending must be a number"
    end
    libgd.gdImageAlphaBlending(im, blending)
    return true
end

_M.saveAlpha = function(im, save_or_not)
    local save = 0
    if save_or_not then
        save = 1
    end
    libgd.gdImageSaveAlpha(im, save)
end

_M.interlace = function(im)
    local ret = libgd.gdImageGetInterlaced(im)
    if ret ~= base.GD_OK then
        return ret
    else
        return nil
    end
end

_M.getClip = function()
    local x1, y1 = util.get_int_ptr_0(), util.get_int_ptr_0()
    local x2, y2 = util.get_int_ptr_0(), util.get_int_ptr_0()
    libgd.gdImageGetClip(x1, y1, x2, y2)
    return tonumber(x1), tonumber(y1), tonumber(x2), tonumber(y2)
end

_M.paletteCopy = function(dst, src)
    if not dst or not src or type(dst) ~= 'cdata' or type(src) ~= 'cdata' then
        return false, "dst src must be specified as cdata<gdImagePtr>"
    end
    libgd.gdImagePaletteCopy(dst, src)
    return true
end

_M.fontCacheSetup = function()
    return libgd.gdFontCacheSetup() == base.GD_ZERO
end

_M.fontCacheShutdown = function()
    libgd.gdFontCacheShutdown()
end

_M.useFontConfig = function(flag)
    local use = false
    if flag then
        use = true
    end
    return libgd.gdFTUseFontConfig(use) ~= base.GD_ZERO
end

_M.stringFT = function(foreground, font, size, ang, x, y, str)
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
    if libgd.gdImageStringFT(nil, brect, foreground, font, size, ang, x, y, str) == nil then
        return brect[1], brect[2], brect[3], brect[4], brect[5], brect[6], brect[7], brect[8]
    end
    return nil
end

_M.stringFTEx = function(foreground, font, size, ang, x, y, str, extr)
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

    local brect = util.get_int_ptr_list(8)
    if libgd.gdImageStringFTEx(nil, brect, foreground, font, size, ang, x, y, str, ex) == nil then
        if bit_band(ex.flags, base.gdFTEX_XSHOW) then
            return brect[1], brect[2], brect[3], brect[4], brect[5], brect[6], brect[7], brect[8], ex.xshow
        end

        if bit_band(ex.flags, base.gdFTEX_RETURNFONTPATHNAME) then
            return brect[1], brect[2], brect[3], brect[4], brect[5], brect[6], brect[7], brect[8], ex.xshow, ex.fontpath
        end
        return brect[1], brect[2], brect[3], brect[4], brect[5], brect[6], brect[7], brect[8]
    end
    return nil
end

_M.gifAnimEndStr = function()
    local size = util.get_int_ptr_0()
    return libgd.gdImageGifAnimEndPtr(size)
end

_M.VERSION = base._VERSION

_M.GD_VERSION = base.gdVersion

_M.MAX_COLORS = base.gdMaxColors

_M.GD2_FMT_RAW = base.GD2_FMT_RAW

_M.GD2_FMT_COMPRESSED = base.GD2_FMT_COMPRESSED

_M.ARC = base.gdArc

_M.CHORD = base.gdChord

_M.PIE = base.gdPie

_M.NO_FILL = base.gdNoFill

_M.EDGED = base.gdEdged

_M.ANTI_ALIASED = base.gdAntiAliased

_M.BRUSHED = base.gdBrushed

_M.STYLED = base.gdStyled

_M.STYLED_BRUSHED = base.gdStyledBrushed

_M.TILED = base.gdTiled

_M.TRANSPARENT = base.gdTransparent

--GD_FREETYPE
_M.FTEX_Unicode = base.gdFTEX_Unicode

_M.FTEX_Shift_JIS = base.gdFTEX_Shift_JIS

_M.FTEX_Big5 = base.gdFTEX_Big5

--GD_GIF
_M.DISPOSAL_NONE = base.gdDisposalNone

_M.DISPOSAL_UNKNOWN = base.gdDisposalUnknown

_M.DISPOSAL_RESTORE_BACKGROUND = base.gdDisposalRestoreBackground

_M.DISPOSAL_RESTORE_PREVIOUS = base.gdDisposalRestorePrevious

--standard gd fonts
_M.FONT_TINY = base.MY_GD_FONT_TINY

_M.FONT_SMALL = base.MY_GD_FONT_SMALL

_M.FONT_MEDIUM = base.MY_GD_FONT_MEDIUM_BOLD

_M.FONT_LARGE = base.MY_GD_FONT_LARGE

_M.FONT_GIANT = base.MY_GD_FONT_GIANT

return _M
