local ffi = require('ffi')
local tostring = tostring
local type = type
local pcall = pcall
local error = error
local io = io

ffi.cdef([[
struct _IO_FILE;
typedef struct _IO_FILE FILE;

static const unsigned int gdMaxColors = 256;
const char * gdVersionString(void);

typedef enum {
	GD_DEFAULT          = 0,
	GD_BELL,
	GD_BESSEL,
	GD_BILINEAR_FIXED,
	GD_BICUBIC,
	GD_BICUBIC_FIXED,
	GD_BLACKMAN,
	GD_BOX,
	GD_BSPLINE,
	GD_CATMULLROM,
	GD_GAUSSIAN,
	GD_GENERALIZED_CUBIC,
	GD_HERMITE,
	GD_HAMMING,
	GD_HANNING,
	GD_MITCHELL,
	GD_NEAREST_NEIGHBOUR,
	GD_POWER,
	GD_QUADRATIC,
	GD_SINC,
	GD_TRIANGLE,
	GD_WEIGHTED4,
	GD_LINEAR,
	GD_METHOD_COUNT = 23
} gdInterpolationMethod;

/* define struct with name and func ptr and add it to gdImageStruct gdInterpolationMethod interpolation; */

/* Interpolation function ptr */
typedef double (* interpolation_method )(double);

typedef struct gdImageStruct {
	/* Palette-based image pixels */
	unsigned char **pixels;
	int sx;
	int sy;
	/* These are valid in palette images only. See also
	   'alpha', which appears later in the structure to
	   preserve binary backwards compatibility */
	int colorsTotal;
	int red[gdMaxColors];
	int green[gdMaxColors];
	int blue[gdMaxColors];
	int open[gdMaxColors];
	/* For backwards compatibility, this is set to the
	   first palette entry with 100% transparency,
	   and is also set and reset by the
	   gdImageColorTransparent function. Newer
	   applications can allocate palette entries
	   with any desired level of transparency; however,
	   bear in mind that many viewers, notably
	   many web browsers, fail to implement
	   full alpha channel for PNG and provide
	   support for full opacity or transparency only. */
	int transparent;
	int *polyInts;
	int polyAllocated;
	struct gdImageStruct *brush;
	struct gdImageStruct *tile;
	int brushColorMap[gdMaxColors];
	int tileColorMap[gdMaxColors];
	int styleLength;
	int stylePos;
	int *style;
	int interlace;
	/* New in 2.0: thickness of line. Initialized to 1. */
	int thick;
	/* New in 2.0: alpha channel for palettes. Note that only
	   Macintosh Internet Explorer and (possibly) Netscape 6
	   really support multiple levels of transparency in
	   palettes, to my knowledge, as of 2/15/01. Most
	   common browsers will display 100% opaque and
	   100% transparent correctly, and do something
	   unpredictable and/or undesirable for levels
	   in between. TBB */
	int alpha[gdMaxColors];
	/* Truecolor flag and pixels. New 2.0 fields appear here at the
	   end to minimize breakage of existing object code. */
	int trueColor;
	int **tpixels;
	/* Should alpha channel be copied, or applied, each time a
	   pixel is drawn? This applies to truecolor images only.
	   No attempt is made to alpha-blend in palette images,
	   even if semitransparent palette entries exist.
	   To do that, build your image as a truecolor image,
	   then quantize down to 8 bits. */
	int alphaBlendingFlag;
	/* Should the alpha channel of the image be saved? This affects
	   PNG at the moment; other future formats may also
	   have that capability. JPEG doesn't. */
	int saveAlphaFlag;

	/* There should NEVER BE ACCESSOR MACROS FOR ITEMS BELOW HERE, so this
	   part of the structure can be safely changed in new releases. */

	/* 2.0.12: anti-aliased globals. 2.0.26: just a few vestiges after
	  switching to the fast, memory-cheap implementation from PHP-gd. */
	int AA;
	int AA_color;
	int AA_dont_blend;

	/* 2.0.12: simple clipping rectangle. These values
	  must be checked for safety when set; please use
	  gdImageSetClip */
	int cx1;
	int cy1;
	int cx2;
	int cy2;

	/* 2.1.0: allows to specify resolution in dpi */
	unsigned int res_x;
	unsigned int res_y;

	/* Selects quantization method, see gdImageTrueColorToPaletteSetMethod() and gdPaletteQuantizationMethod enum. */
	int paletteQuantizationMethod;
	/* speed/quality trade-off. 1 = best quality, 10 = best speed. 0 = method-specific default.
	   Applicable to GD_QUANT_LIQ and GD_QUANT_NEUQUANT. */
	int paletteQuantizationSpeed;
	/* Image will remain true-color if conversion to palette cannot achieve given quality.
	   Value from 1 to 100, 1 = ugly, 100 = perfect. Applicable to GD_QUANT_LIQ.*/
	int paletteQuantizationMinQuality;
	/* Image will use minimum number of palette colors needed to achieve given quality. Must be higher than paletteQuantizationMinQuality
	   Value from 1 to 100, 1 = ugly, 100 = perfect. Applicable to GD_QUANT_LIQ.*/
	int paletteQuantizationMaxQuality;
	gdInterpolationMethod interpolation_id;
	interpolation_method interpolation;
}
gdImage;

typedef gdImage *gdImagePtr;

typedef struct {
	int x, y;
}
gdPoint, *gdPointPtr;

typedef struct {
	/* # of characters in font */
	int nchars;
	/* First character is numbered... (usually 32 = space) */
	int offset;
	/* Character width and height */
	int w;
	int h;
	/* Font data; array of characters, one row after another.
	   Easily included in code, also easily loaded from
	   data files. */
	char *data;
}
gdFont;

/* Text functions take these. */
typedef gdFont *gdFontPtr;

typedef struct {
	int flags;		/* Logical OR of gdFTEX_ values */
	double linespacing;	/* fine tune line spacing for '\n' */
	int charmap;		/* TBB: 2.0.12: may be gdFTEX_Unicode,
				   gdFTEX_Shift_JIS, gdFTEX_Big5,
				   or gdFTEX_Adobe_Custom;
				   when not specified, maps are searched
				   for in the above order. */
	int hdpi;                /* if (flags & gdFTEX_RESOLUTION) */
	int vdpi;		 /* if (flags & gdFTEX_RESOLUTION) */
	char *xshow;             /* if (flags & gdFTEX_XSHOW)
				    then, on return, xshow is a malloc'ed
				    string containing xshow position data for
				    the last string.

				    NB. The caller is responsible for gdFree'ing
				    the xshow string.
				 */
	char *fontpath;	         /* if (flags & gdFTEX_RETURNFONTPATHNAME)
				    then, on return, fontpath is a malloc'ed
				    string containing the actual font file path name
				    used, which can be interesting when fontconfig
				    is in use.

				    The caller is responsible for gdFree'ing the
				    fontpath string.
				 */

}
gdFTStringExtra, *gdFTStringExtraPtr;

void gdImageDestroy (gdImagePtr im);
void gdFree (void *m);

gdImagePtr gdImageCreate (int sx, int sy);
gdImagePtr gdImageCreateTrueColor (int sx, int sy);
gdImagePtr gdImageCreatePaletteFromTrueColor (gdImagePtr im, int ditherFlag,
							   int colorsWanted);
int gdImageTrueColorToPalette (gdImagePtr im, int ditherFlag,
					    int colorsWanted);
gdImagePtr gdImageCreateFromJpeg (FILE * infile);
gdImagePtr gdImageCreateFromJpegPtr (int size, void *data);

gdImagePtr gdImageCreateFromGif (FILE * fd);
gdImagePtr gdImageCreateFromGifPtr (int size, void *data);

gdImagePtr gdImageCreateFromPng (FILE * fd);
gdImagePtr gdImageCreateFromPngPtr (int size, void *data);

gdImagePtr gdImageCreateFromGd (FILE * in);
gdImagePtr gdImageCreateFromGdPtr (int size, void *data);

gdImagePtr gdImageCreateFromGd2 (FILE * in);
gdImagePtr gdImageCreateFromGd2Ptr (int size, void *data);

gdImagePtr gdImageCreateFromGd2Part (FILE * in, int srcx, int srcy, int w, int h);
gdImagePtr gdImageCreateFromGd2PartPtr (int size, void *data, int srcx, int srcy, int w, int h);

gdImagePtr gdImageCreateFromXbm (FILE * in);
gdImagePtr gdImageCreateFromXpm (char *filename);

gdImagePtr gdImageCreateFromWebp (FILE * inFile);
gdImagePtr gdImageCreateFromWebpPtr (int size, void *data);

gdImagePtr gdImageCreateFromTiff(FILE *inFile);
gdImagePtr gdImageCreateFromTiffPtr(int size, void *data);

void gdImageJpeg (gdImagePtr im, FILE * out, int quality);
void * gdImageJpegPtr (gdImagePtr im, int *size, int quality);

void gdImagePng (gdImagePtr im, FILE * out);
void gdImagePngEx (gdImagePtr im, FILE * out, int level);
void * gdImagePngPtr (gdImagePtr im, int *size);
void * gdImagePngPtrEx (gdImagePtr im, int *size, int level);

void gdImageGif (gdImagePtr im, FILE * out);
void * gdImageGifPtr (gdImagePtr im, int *size);

void gdImageGd (gdImagePtr im, FILE * out);
void * gdImageGdPtr (gdImagePtr im, int *size);

void gdImageGd2 (gdImagePtr im, FILE * out, int cs, int fmt);
void * gdImageGd2Ptr (gdImagePtr im, int cs, int fmt, int *size);

void gdImageWBMP (gdImagePtr image, int fg, FILE * out);
void * gdImageWBMPPtr (gdImagePtr im, int *size, int fg);

void gdImageBmp(gdImagePtr im, FILE *outFile, int compression);
void * gdImageBmpPtr(gdImagePtr im, int *size, int compression);

void gdImageTiff(gdImagePtr im, FILE *outFile);
void * gdImageTiffPtr(gdImagePtr im, int *size);

void gdImageWebp (gdImagePtr im, FILE * outFile);
void gdImageWebpEx (gdImagePtr im, FILE * outFile, int quantization);
void * gdImageWebpPtr (gdImagePtr im, int *size);
void * gdImageWebpPtrEx (gdImagePtr im, int *size, int quantization);

int gdImageColorAllocate(gdImagePtr im, int r, int g, int b);
int gdImageColorAllocateAlpha(gdImagePtr im, int r, int g, int b, int a);

int gdImageColorClosest(gdImagePtr im, int r, int g, int b);
int gdImageColorClosestAlpha(gdImagePtr im, int r, int g, int b, int a);
int gdImageColorClosestHWB(gdImagePtr im, int r, int g, int b);

int gdImageColorExact(gdImagePtr im, int r, int g, int b);
int gdImageColorExactAlpha(gdImagePtr im, int r, int g, int b, int a);

int gdImageColorResolve(gdImagePtr im, int r, int g, int b);
int gdImageColorResolveAlpha(gdImagePtr im, int r, int g, int b, int a);

int gdImageColorsTotal(gdImagePtr im);
int gdImageRed(gdImagePtr im, int c);
int gdImageBlue(gdImagePtr im, int c);
int gdImageGreen(gdImagePtr im, int c);
int gdImageAlpha(gdImagePtr im, int color);

int gdImageGetInterlaced(gdImagePtr im);
int gdImageGetTransparent(gdImagePtr im);
void gdImageColorTransparent(gdImagePtr im, int c);
void gdImageColorDeallocate(gdImagePtr im, int c);

int gdImageSX(gdImagePtr im);
int gdImageSY(gdImagePtr im);

int gdImageBoundsSafe(gdImagePtr im, int x, int y);
int gdImageGetPixel(gdImagePtr im, int x, int y);
void gdImageSetPixel(gdImagePtr im, int x, int y, int color);

void gdImageLine(gdImagePtr im, int x1, int y1, int x2, int y2, int c);
void gdImageRectangle(gdImagePtr im, int x1, int y1, int x2, int y2, int c);
void gdImageFilledRectangle(gdImagePtr im, int x1, int y1, int x2, int y2, int c);

void gdImagePolygon(gdImagePtr im, gdPointPtr points, int pointsTotal, int color);
void gdImageFilledPolygon(gdImagePtr im, gdPointPtr points, int pointsTotal, int color);
void gdImageOpenPolygon(gdImagePtr im, gdPointPtr points, int pointsTotal, int color);

void gdImageArc(gdImagePtr im, int cx, int cy, int w, int h, int s, int e, int color);
void gdImageFilledArc(gdImagePtr im, int cx, int cy, int w, int h, int s, int e, int color, int style);
void gdImageFilledEllipse(gdImagePtr im, int cx, int cy, int w, int h, int color);
void gdImageFill(gdImagePtr im, int x, int y, int color);
void gdImageFillToBorder(gdImagePtr im, int x, int y, int border, int color);

void gdImageSetAntiAliased(gdImagePtr im, int c);
void gdImageSetAntiAliasedDontBlend(gdImagePtr im, int c);

void gdImageSetBrush(gdImagePtr im, gdImagePtr brush);
void gdImageSetTile(gdImagePtr im, gdImagePtr tile);
void gdImageSetStyle(gdImagePtr im, int *style, int styleLength);
void gdImageSetThickness(gdImagePtr im, int thickness);
void gdImageAlphaBlending(gdImagePtr im, int blending);
void gdImageSaveAlpha(gdImagePtr im, int saveFlag);

void gdImageString(gdImagePtr im, gdFontPtr font, int x, int y,
        unsigned char *s, int color);
void gdImageStringUp(gdImagePtr im, gdFontPtr font, int x, int y,
        unsigned char *s, int color);
void gdImageChar(gdImagePtr im, gdFontPtr font, int x, int y,
            int c, int color);
void gdImageCharUp(gdImagePtr im, gdFontPtr font, int x, int y,
            int c, int color);

void gdImageCopy(gdImagePtr dst, gdImagePtr src, int dstX, int dstY,
            int srcX, int srcY, int w, int h);
void gdImageCopyResized(gdImagePtr dst, gdImagePtr src, int dstX,
            int dstY, int srcX, int srcY, int destW, int destH,
            int srcW, int srcH);
void gdImageCopyResampled(gdImagePtr dst, gdImagePtr src, int dstX,
        int dstY, int srcX, int srcY, int destW, int destH, int srcW,
        int srcH);
void gdImageCopyRotated(gdImagePtr dst, gdImagePtr src, double dstX,
        double dstY, int srcX, int srcY, int srcW, int srcH, int angle);
void gdImageCopyMerge(gdImagePtr dst, gdImagePtr src, int dstX,
        int dstY, int srcX, int srcY, int w, int h, int pct);
void gdImageCopyMergeGray(gdImagePtr dst, gdImagePtr src, int dstX,
        int dstY, int srcX, int srcY, int w, int h, int pct);
void gdImagePaletteCopy(gdImagePtr dst, gdImagePtr src);

void gdImageSquareToCircle(gdImagePtr im, int radius);
void gdImageSharpen(gdImagePtr im, int pct);
void gdImageSetClip(gdImagePtr im, int x1, int y1, int x2, int y2);
void gdImageGetClip(gdImagePtr im, int *x1, int *y1, int *x2, int *y2);

int gdFTUseFontConfig(int flag);
int gdFontCacheSetup(void);
void gdFontCacheShutdown(void);

char * gdImageStringFT (gdImage * im, int *brect, int fg, const char *fontlist,
                                     double ptsize, double angle, int x, int y,
                                     const char *string);
char * gdImageStringFTEx (gdImage * im, int *brect, int fg, const char *fontlist,
                                       double ptsize, double angle, int x, int y,
                                       const char *string, gdFTStringExtraPtr strex);
char *gdImageStringFTCircle(gdImagePtr im, int cx, int cy, double radius,
                double textRadius, double fillPortion, char *font,
                double points, char *top, char *bottom, int fgcolor);

void gdImageGifAnimBegin(gdImagePtr im, FILE *out, int GlobalCM, int Loops);
void gdImageGifAnimAdd(gdImagePtr im, FILE *out, int LocalCM, int LeftOfs,
            int TopOfs, int Delay, int Disposal, gdImagePtr previm);
void gdImageGifAnimEnd(FILE *out);
void* gdImageGifAnimBeginPtr(gdImagePtr im, int *size, int GlobalCM,
        int Loops);
void* gdImageGifAnimAddPtr(gdImagePtr im, int *size, int LocalCM,
    int LeftOfs, int TopOfs, int Delay, int Disposal, gdImagePtr previm);
void* gdImageGifAnimEndPtr(int *size);
]])



local try_to_load
try_to_load = function(...)
    local out
    local _list_0 = {
        ...
    }
    for _index_0 = 1, #_list_0 do
        local _continue_0 = false
        repeat
            local name = _list_0[_index_0]
            if "function" == type(name) then
                name = name()
                if not (name) then
                    _continue_0 = true
                    break
                end
            end
            if pcall(function()
                    out = ffi.load(name)
                end) then
                return out
            end
            _continue_0 = true
        until true
        if not _continue_0 then
            break
        end
    end
    return error("Failed to load gd (" .. tostring(...) .. ")")
end

local lib = try_to_load(function()
    return "libgd.so"
end)

return lib
