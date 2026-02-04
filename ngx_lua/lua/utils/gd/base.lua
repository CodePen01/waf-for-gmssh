local modulename = "gdBase"
local _M = { _VERSION = '2.2.5.1', _NAME = modulename }

local ffi = require('ffi')
local libgd = require('gd.libgd')

local tonumber = tonumber
local ffi_str = ffi.string

_M.gdVersion = '2.2.5.1'

_M.gdMaxColors = tonumber(libgd.gdMaxColors)

_M.GD2_FMT_RAW = 1

_M.GD2_FMT_COMPRESSED = 2

_M.gdArc = 0

_M.gdChord = 1

_M.gdPie = _M.gdArc

_M.gdNoFill = 2

_M.gdEdged = 4

_M.gdAntiAliased = -7

_M.gdBrushed = -3

_M.gdStyled = -2

_M.gdStyledBrushed = -4

_M.gdTiled = -5

_M.gdTransparent = -6

_M.gdFTEX_Unicode = 0

_M.gdFTEX_Shift_JIS = 1

_M.gdFTEX_Big5 = 2

_M.gdDisposalNone = 1

_M.gdDisposalUnknown = 0

_M.gdDisposalRestoreBackground = 2

_M.gdDisposalRestorePrevious = 3

_M.MY_GD_FONT_TINY = 4

_M.MY_GD_FONT_SMALL = 0

_M.MY_GD_FONT_MEDIUM_BOLD = 2

_M.MY_GD_FONT_LARGE = 1

_M.MY_GD_FONT_GIANT = 3

_M.GD_IMAGE_PTR_TYPENAME = "gdImagePtr_handle"

_M.gdFTEX_XSHOW = 16

_M.gdFTEX_RETURNFONTPATHNAME = 128

_M.GD_OK = 1

_M.GD_ERR = -1

_M.GD_ZERO = 0

return _M
