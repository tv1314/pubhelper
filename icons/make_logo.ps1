# 生成「公网小助手」应用图标：NAS -> 箭头 -> 云（公网）
# 设计：蓝紫渐变圆角方底 + 白色线条字形，深色描边粗、小尺寸也可辨认
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

$S = 1024
$bmp = New-Object System.Drawing.Bitmap $S, $S
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
$g.Clear([System.Drawing.Color]::Transparent)

function New-RoundedPath([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = [float]($r * 2)
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc(($x + $w - $d), $y, $d, $d, 270, 90)
    $p.AddArc(($x + $w - $d), ($y + $h - $d), $d, $d, 0, 90)
    $p.AddArc($x, ($y + $h - $d), $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

# ---------- 背景：蓝紫渐变圆角方块 ----------
$bgPath = New-RoundedPath 0 0 $S $S 224
$bg = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    (New-Object System.Drawing.Point(0, 0)),
    (New-Object System.Drawing.Point($S, $S)),
    [System.Drawing.Color]::FromArgb(255, 76, 141, 255),
    [System.Drawing.Color]::FromArgb(255, 123, 92, 255))
$g.FillPath($bg, $bgPath)

# ---------- 字形：白色，粗描边 ----------
$white = [System.Drawing.Color]::White
$pen = New-Object System.Drawing.Pen $white, 56
$pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round

# 1) 左侧 NAS 机箱（略扁，避免压过云）
$srv = New-RoundedPath 168 415 205 180 42
$g.DrawPath($pen, $srv)
# 机箱内的三条硬盘槽位（细线，避免糊成一片）
$pen2 = New-Object System.Drawing.Pen $white, 26
$pen2.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$pen2.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$g.DrawLine($pen2, 220, 470, 320, 470)
$g.DrawLine($pen2, 220, 505, 320, 505)
$g.DrawLine($pen2, 220, 540, 320, 540)

# 2) 中间箭头（数据出站）
$g.DrawLine($pen, 393, 505, 512, 505)
$head = @(
    (New-Object System.Drawing.PointF(592, 505)),
    (New-Object System.Drawing.PointF(510, 450)),
    (New-Object System.Drawing.PointF(510, 560))
)
$g.FillPolygon((New-Object System.Drawing.SolidBrush $white), $head)

# 3) 右侧云（公网）：三团 + 一条平底，保证轮廓平滑无缺口
$wb = New-Object System.Drawing.SolidBrush $white
$g.FillRectangle($wb, 610, 505, 262, 80)   # 平底先画，避免底部缺口
$g.FillEllipse($wb, 615, 455, 110, 110)    # 左团
$g.FillEllipse($wb, 672, 398, 156, 156)    # 顶团
$g.FillEllipse($wb, 762, 452, 110, 110)    # 右团

# 输出到脚本所在目录，不写死本机绝对路径
$out = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
New-Item -ItemType Directory -Force -Path $out | Out-Null
$master = Join-Path $out 'logo_1024.png'
$bmp.Save($master, [System.Drawing.Imaging.ImageFormat]::Png)

# ---------- 缩放出各个尺寸 ----------
$targets = @(
    @('icon_32.png', 32),
    @('icon_64.png', 64),
    @('icon_128.png', 128),
    @('icon_256.png', 256),
    @('icon_512.png', 512),
    @('ICON.PNG', 256),
    @('ICON_256.PNG', 256)
)
foreach ($t in $targets) {
    $k = $t[0]
    $n = [int]$t[1]
    $dst = New-Object System.Drawing.Bitmap $n, $n
    $gd = [System.Drawing.Graphics]::FromImage($dst)
    $gd.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $gd.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $gd.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $gd.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $gd.Clear([System.Drawing.Color]::Transparent)
    $gd.DrawImage($bmp, 0, 0, $n, $n)
    $gd.Dispose()
    $dst.Save((Join-Path $out $k), [System.Drawing.Imaging.ImageFormat]::Png)
    $dst.Dispose()
}

$g.Dispose()
$bmp.Dispose()

# 注意：Windows 文件名不区分大小写，icon_256.png 与 ICON_256.PNG 无法共存于同一目录，
# 顶层包所需的 ICON_256.PNG 在上传后由服务器端复制生成。

Get-ChildItem $out -Filter *.png | Sort-Object Name | ForEach-Object {
    "{0,-14} {1,6} bytes" -f $_.Name, $_.Length
}
