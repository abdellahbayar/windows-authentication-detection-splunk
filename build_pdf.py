"""Create the illustrated English PDF from project content and screenshots."""
import html
import json
import textwrap
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak, Preformatted, KeepTogether
from PIL import Image as PILImage

ROOT = Path(__file__).resolve().parent
WORKSPACE = ROOT.parents[2]
OUTPUT = WORKSPACE / "output/pdf/Windows-Authentication-Detection-with-Splunk.pdf"
pdfmetrics.registerFont(TTFont("LabArial", r"C:\Windows\Fonts\arial.ttf"))
pdfmetrics.registerFont(TTFont("LabArialBold", r"C:\Windows\Fonts\arialbd.ttf"))
pdfmetrics.registerFont(TTFont("LabMono", r"C:\Windows\Fonts\consola.ttf"))
pdfmetrics.registerFontFamily("LabArial", normal="LabArial", bold="LabArialBold")
NAVY = colors.HexColor("#112640")
BLUE = colors.HexColor("#17649c")
MUTED = colors.HexColor("#5c6f84")
styles = {
    "title": ParagraphStyle("title", fontName="LabArialBold", fontSize=24, leading=29, textColor=NAVY, spaceAfter=15),
    "body": ParagraphStyle("body", fontName="LabArial", fontSize=10.1, leading=14.4, textColor=colors.HexColor("#26394b"), spaceAfter=9),
    "bullet": ParagraphStyle("bullet", fontName="LabArial", fontSize=9.4, leading=13, leftIndent=11, firstLineIndent=-8, spaceAfter=5),
    "caption": ParagraphStyle("caption", fontName="LabArial", fontSize=8, leading=11, textColor=MUTED, spaceBefore=5, spaceAfter=12),
    "code": ParagraphStyle("code", fontName="LabMono", fontSize=7.7, leading=10.8, textColor=NAVY, backColor=colors.HexColor("#eef3f8"), borderPadding=9, spaceBefore=8, spaceAfter=12),
    "tag": ParagraphStyle("tag", fontName="LabArialBold", fontSize=8.2, leading=11, textColor=BLUE, spaceAfter=9),
}

def decorate(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(NAVY); canvas.rect(0, h-34, w, 34, stroke=0, fill=1)
    canvas.setFont("LabArialBold", 9); canvas.setFillColor(colors.white)
    canvas.drawString(38, h-22, "AB / WINDOWS AUTHENTICATION DETECTION WITH SPLUNK")
    canvas.setStrokeColor(colors.HexColor("#d8e2ed")); canvas.line(38, 39, w-38, 39)
    canvas.setFont("LabArial", 7.2); canvas.setFillColor(MUTED)
    canvas.drawString(38, 27, "Abdellah Bayar | Windows Authentication Detection Lab")
    canvas.drawRightString(w-38, 27, str(doc.page))
    canvas.restoreState()

def cover(canvas, doc):
    from portfolio_cover import draw_portfolio_cover
    draw_portfolio_cover(canvas, [
        ('Environment and installation', 2),
        ('Splunk app and data ingestion', 5),
        ('Event fields and detection logic', 7),
        ('Expected findings and dashboard', 10),
        ('Validation and alert testing', 12),
        ('Investigation and real-event extension', 14),
        ('Troubleshooting and references', 16),
    ], second='A step-by-step synthetic-data reproduction guide')

def build():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    pages = json.loads((ROOT / "chapters.json").read_text(encoding="utf-8"))
    doc = SimpleDocTemplate(str(OUTPUT), pagesize=A4, leftMargin=38, rightMargin=38,
                            topMargin=57, bottomMargin=53, title="Windows Authentication Detection with Splunk - Practical Guide",
                            author="Abdellah Bayar")
    story=[Spacer(1, 10), PageBreak()]
    for i, page in enumerate(pages[1:]):
        if i: story.append(PageBreak())
        story.append(Paragraph(page.get("tag", "PRACTICAL GUIDE / AUTHENTICATION DETECTION LAB"), styles["tag"]))
        story.append(Paragraph(html.escape(page["title"]), styles["title"]))
        for p in page.get("paragraphs", []): story.append(Paragraph(html.escape(p), styles["body"]))
        name = page.get("image") or ((page["screen"] + ".png") if page.get("screen") else None)
        if name:
            path=ROOT / "screenshots" / name
            with PILImage.open(path) as image: w,h=image.size
            max_h=290 if page.get("image") else 330
            scale=min(519/w,max_h/h)
            story.append(Image(str(path), width=w*scale, height=h*scale, hAlign="CENTER"))
            caption=("Original Ubuntu terminal capture: lab environment preparation, 8 October 2026." if page.get("image") else
                     "Illustrative local preview of expected results using the synthetic dataset. Full-resolution image available in screenshots/.")
            story.append(Paragraph(caption, styles["caption"]))
        if page.get("code"):
            lines=[]
            for line in page["code"].splitlines():
                lines.extend(textwrap.wrap(line, width=110, break_long_words=False, break_on_hyphens=False, subsequent_indent="  ") or [""])
            story.append(Preformatted("\n".join(lines), styles["code"]))
            story.append(Paragraph("Copy commands from GUIDE.md or queries/ to avoid line breaks introduced by page layout.", styles["caption"]))
        for b in page.get("bullets", []): story.append(Paragraph("- " + html.escape(b), styles["bullet"]))
        for title,url in page.get("links", []):
            story.append(Paragraph(f'<a href="{html.escape(url, quote=True)}" color="#17649c">{html.escape(title)}</a>', styles["body"]))
        story.append(Spacer(1,8))
    doc.build(story, onFirstPage=cover, onLaterPages=decorate)
    import pypdf
    reader=pypdf.PdfReader(str(OUTPUT))
    text="\n".join(p.extract_text() or "" for p in reader.pages)
    assert "synthetic-data reproduction guide" in text and "Detection with Splunk" in (reader.pages[0].extract_text() or "")
    assert "Abdellah Bayar | Windows Authentication Detection Lab" in text
    assert len(reader.pages)>=17
    (ROOT / "pdf-verification.json").write_text(json.dumps({"pages":len(reader.pages),"textChecks":"PASS","file":OUTPUT.name},indent=2))
    print(json.dumps({"pdf":str(OUTPUT),"pages":len(reader.pages)}))

if __name__ == "__main__": build()
