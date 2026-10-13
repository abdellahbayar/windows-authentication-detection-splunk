"""The established SOC lab portfolio cover: serif title, corner circle and contents."""
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

for name, filename in [('CoverBody','segoeui.ttf'),('CoverBold','segoeuib.ttf'),('CoverTitle','georgiab.ttf')]:
    pdfmetrics.registerFont(TTFont(name, 'C:/Windows/Fonts/' + filename))

def draw_portfolio_cover(canvas, contents, *, category='WINDOWS AUTHENTICATION / SPLUNK',
                         lines=('Windows','Authentication','Detection with Splunk'),
                         subtitle='From authentication records to a detection candidate',
                         second='Synthetic event scenarios and a rolling-window SPL rule'):
    w,h=A4; left=22*mm
    canvas.saveState()
    canvas.setFillColor(colors.HexColor('#0B172A')); canvas.rect(0,0,w,h,fill=1,stroke=0)
    canvas.setFillColor(colors.HexColor('#0D2B3D')); canvas.circle(w+80,h-110,285,fill=1,stroke=0)
    canvas.setStrokeColor(colors.HexColor('#174256')); canvas.setLineWidth(.8)
    canvas.circle(w+80,h-110,310,fill=0,stroke=1)
    canvas.setFillColor(colors.HexColor('#08C6DD')); canvas.setFont('CoverBold',10)
    canvas.drawString(left,h-43*mm,'SECURITY LABS  /  04')
    canvas.setFillColor(colors.HexColor('#A7BECF')); canvas.setFont('CoverBody',10)
    canvas.drawString(left,h-55*mm,category)
    canvas.setFillColor(colors.white); canvas.setFont('CoverTitle',35)
    for i,line in enumerate(lines):
        assert pdfmetrics.stringWidth(line,'CoverTitle',35)<=w-2*left,line
        canvas.drawString(left,h-87*mm-i*43,line)
    canvas.setFillColor(colors.HexColor('#AEC2D2')); canvas.setFont('CoverBody',12)
    canvas.drawString(left,h-140*mm,subtitle)
    canvas.setFont('CoverBody',10.5); canvas.drawString(left,h-151*mm,second)
    iy=h-174*mm
    canvas.setStrokeColor(colors.HexColor('#205067')); canvas.line(left,iy+16,w-left,iy+16)
    spacing=24 if len(contents)>5 else 27
    for i,(label,page) in enumerate(contents):
        y=iy-i*spacing
        canvas.setFillColor(colors.HexColor('#D0DFE9')); canvas.setFont('CoverBody',10.5)
        canvas.drawString(left,y,label)
        canvas.setFillColor(colors.HexColor('#08C6DD')); canvas.drawRightString(w-left,y,str(page).zfill(2))
        canvas.setStrokeColor(colors.HexColor('#19394B')); canvas.line(left,y-10,w-left,y-10)
    canvas.setFillColor(colors.white); canvas.setFont('CoverBold',13)
    canvas.drawString(left,35*mm,'Abdellah Bayar')
    canvas.setFillColor(colors.HexColor('#A7BECF')); canvas.setFont('CoverBody',9.5)
    canvas.drawString(left,27*mm,'SOC LAB PORTFOLIO')
    canvas.drawString(left,20*mm,'13 October 2026')
    canvas.restoreState()
