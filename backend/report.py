from datetime import datetime
from io import BytesIO

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

NAVY = colors.HexColor("#0B1F3A")
BLUE = colors.HexColor("#1F6FEB")
RED = colors.HexColor("#C62828")
AMBER = colors.HexColor("#E08A00")
GREEN = colors.HexColor("#2E7D32")
GREY = colors.HexColor("#5B6676")
LIGHT = colors.HexColor("#F3F5F9")
LINE = colors.HexColor("#D5DAE3")

SEV_COLOR = {"High": RED, "Medium": AMBER, "Low": GREEN}
STATUS_COLOR = {"Escalated": RED, "Approved": GREEN, "Rejected": GREY, "Pending": AMBER}

H1 = ParagraphStyle("H1", fontName="Helvetica-Bold", fontSize=13, textColor=NAVY, spaceBefore=14, spaceAfter=6, keepWithNext=1)
BODY = ParagraphStyle("BODY", fontName="Helvetica", fontSize=9.5, leading=14, textColor=colors.HexColor("#222B38"), alignment=TA_LEFT)
SMALL = ParagraphStyle("SMALL", fontName="Helvetica", fontSize=8, leading=10.5, textColor=colors.HexColor("#222B38"))
MONO = ParagraphStyle("MONO", fontName="Courier", fontSize=7.5, leading=9.5, textColor=colors.HexColor("#222B38"))
CELL_HEAD = ParagraphStyle("CH", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=colors.white)
NOTE = ParagraphStyle("NOTE", fontName="Helvetica-Oblique", fontSize=8.5, leading=12, textColor=GREY)

WEIGHTS = [
    ("Source reputation", "30%", "Trust level of the feed that reported the indicator"),
    ("Times seen", "25%", "How often the indicator was observed (capped at 100)"),
    ("Recency", "20%", "How recently the indicator first appeared"),
    ("Asset relevance", "15%", "How relevant the indicator type is to our environment"),
    ("Malware severity", "10%", "Severity of the associated malware family"),
]


def _tags(ind):
    return [t for t in (ind.tags or "").split(",") if t]


def _pill(text, color):
    return Paragraph('<font color="%s"><b>%s</b></font>' % (color.hexval().replace("0x", "#"), text), SMALL)


def _short(value):
    return value if len(value) <= 34 else value[:16] + "..." + value[-8:]


def _summary_table(total, high, pending, escalated):
    items = [("Total indicators", total, NAVY), ("High risk", high, RED),
             ("Pending review", pending, AMBER), ("Escalated", escalated, BLUE)]
    cells = []
    for label, val, col in items:
        cells.append([
            Paragraph('<font size="20" color="%s"><b>%d</b></font>' % (col.hexval().replace("0x", "#"), val), SMALL),
            Paragraph('<font color="#5B6676">%s</font>' % label, SMALL),
        ])
    t = Table([[c[0] for c in cells], [c[1] for c in cells]], colWidths=[43.5 * mm] * 4, rowHeights=[11 * mm, 6 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
        ("LINEAFTER", (0, 0), (-2, -1), 3, colors.white),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
    ]))
    return t


def _charts(by_sev, by_status):
    W, Hh = 174 * mm, 56 * mm
    d = Drawing(W, Hh)
    d.add(String(0, Hh - 10, "Severity distribution", fontName="Helvetica-Bold", fontSize=9, fillColor=NAVY))
    d.add(String(W / 2 + 10, Hh - 10, "Review status", fontName="Helvetica-Bold", fontSize=9, fillColor=NAVY))

    sev_vals = [by_sev["High"], by_sev["Medium"], by_sev["Low"]]
    if sum(sev_vals) > 0:
        pie = Pie()
        pie.x, pie.y, pie.width, pie.height = 10, 18, 100, 100
        pie.data = sev_vals
        pie.labels = None
        pie.sideLabels = 0
        pie.slices.strokeColor = colors.white
        pie.slices.strokeWidth = 1.5
        for i, c in enumerate([RED, AMBER, GREEN]):
            pie.slices[i].fillColor = c
        d.add(pie)
    for i, (name, c) in enumerate([("High", RED), ("Medium", AMBER), ("Low", GREEN)]):
        y = Hh - 50 - i * 18
        d.add(Rect(135, y, 9, 9, fillColor=c, strokeColor=None))
        d.add(String(150, y + 1, "%s: %d" % (name, by_sev[name]), fontName="Helvetica", fontSize=9, fillColor=colors.HexColor("#222B38")))

    cats = ["Pending", "Approved", "Rejected", "Escalated"]
    bar = VerticalBarChart()
    bar.x, bar.y, bar.width, bar.height = W / 2 + 35, 18, W / 2 - 55, Hh - 45
    bar.data = [[by_status.get(c, 0) for c in cats]]
    bar.categoryAxis.categoryNames = cats
    bar.categoryAxis.labels.fontName = "Helvetica"
    bar.categoryAxis.labels.fontSize = 8
    bar.valueAxis.valueMin = 0
    mx = max(bar.data[0]) or 1
    bar.valueAxis.valueMax = mx + max(1, round(mx * 0.15))
    bar.valueAxis.labels.fontSize = 8
    bar.valueAxis.strokeColor = LINE
    bar.valueAxis.visibleGrid = 1
    bar.valueAxis.gridStrokeColor = LINE
    bar.bars.strokeColor = None
    bar.bars.fillColor = BLUE
    for i, c in enumerate(cats):
        bar.bars[(0, i)].fillColor = STATUS_COLOR[c]
    bar.barLabelFormat = "%d"
    bar.barLabels.nudge = 7
    bar.barLabels.fontSize = 8
    bar.groupSpacing = 12
    d.add(bar)
    return d


def _recommendations(items, by_sev, pending_high):
    high = [i for i in items if i.severity == "High"]
    recs = []
    hi_ips = [i for i in high if i.type == "ip"]
    hi_dom = [i for i in high if i.type == "domain"]
    hi_hash = [i for i in high if i.type == "hash"]
    if hi_ips:
        recs.append("<b>Block %d high-risk IP address%s</b> at the perimeter firewall, starting with %s."
                    % (len(hi_ips), "" if len(hi_ips) == 1 else "es", ", ".join(i.value for i in hi_ips[:3])))
    if hi_dom:
        recs.append("<b>Block or sinkhole %d high-risk domain%s</b> at the DNS and web proxy layer, starting with %s."
                    % (len(hi_dom), "" if len(hi_dom) == 1 else "s", ", ".join(i.value for i in hi_dom[:3])))
    if hi_hash:
        recs.append("<b>Add %d high-risk file hash%s</b> to the endpoint protection blocklist and run a retro-hunt for prior executions."
                    % (len(hi_hash), "" if len(hi_hash) == 1 else "es"))
    all_tags = {t for i in items for t in _tags(i)}
    if "ransomware" in all_tags:
        recs.append("<b>Ransomware activity is present.</b> Verify that offline backups are intact and critical systems are patched.")
    if "phishing" in all_tags:
        recs.append("<b>Phishing infrastructure is present.</b> Tighten email filtering and send a short awareness reminder to staff.")
    if pending_high:
        recs.append("<b>Review the %d pending high-risk indicator%s within 24 hours.</b> Unreviewed high-risk items are the largest gap in coverage."
                    % (pending_high, "" if pending_high == 1 else "s"))
    recs.append("<b>Share approved indicators</b> with partner organisations using the STIX 2.1 export, marked TLP:AMBER.")
    recs.append("<b>Scan outbound documents and tickets</b> with the DLP module to catch leaked identifiers and credentials early.")
    return recs


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.line(18 * mm, 15 * mm, A4[0] - 18 * mm, 15 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(GREY)
    canvas.drawString(18 * mm, 10 * mm, "ThreatLens  |  TLP:AMBER  |  For authorised recipients only")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, "Page %d" % doc.page)
    canvas.restoreState()


def build_report(items):
    scored = [i for i in items if i.score is not None]
    scored.sort(key=lambda i: i.score, reverse=True)
    total = len(scored)
    by_sev = {"High": 0, "Medium": 0, "Low": 0}
    by_status = {"Pending": 0, "Approved": 0, "Rejected": 0, "Escalated": 0}
    by_type = {}
    for i in scored:
        by_sev[i.severity] = by_sev.get(i.severity, 0) + 1
        by_status[i.status] = by_status.get(i.status, 0) + 1
        by_type[i.type] = by_type.get(i.type, 0) + 1
    pending_high = sum(1 for i in scored if i.severity == "High" and i.status == "Pending")
    reviewed = total - by_status["Pending"]
    now = datetime.now()

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=22 * mm,
                            title="ThreatLens Threat Intelligence Report", author="ThreatLens")
    s = []

    banner = Table([[Paragraph('<font color="white" size="19"><b>ThreatLens</b></font><br/>'
                               '<font color="#BFD3F2" size="10">Threat Intelligence Triage Report</font>', BODY),
                     Paragraph('<font color="#BFD3F2" size="8.5">Generated %s<br/>Classification: <b><font color="white">TLP:AMBER</font></b></font>'
                               % now.strftime("%d %b %Y, %H:%M"), ParagraphStyle("r", parent=BODY, alignment=2))]],
                   colWidths=[110 * mm, 64 * mm])
    banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("LEFTPADDING", (0, 0), (-1, -1), 12),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 12), ("TOPPADDING", (0, 0), (-1, -1), 12),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 12), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    s += [banner, Spacer(1, 10)]

    s.append(Paragraph("1. Executive summary", H1))
    top = scored[0] if scored else None
    summary = ("This report covers <b>%d</b> unique threat indicators ingested from external feeds, after duplicate removal. "
               "Each indicator was scored from 0 to 100 and classed as High (70 and above), Medium (50 to 69) or Low (below 50). "
               "<b>%d</b> indicators are rated High and <b>%d</b> have been reviewed by an analyst so far (%d approved, %d rejected, %d escalated)."
               % (total, by_sev["High"], reviewed, by_status["Approved"], by_status["Rejected"], by_status["Escalated"]))
    if top:
        summary += (" The highest-scoring indicator is <font name='Courier'>%s</font> (%s, score %d)." % (_short(top.value), top.type, top.score))
    if pending_high:
        summary += " <b>%d High-risk indicator%s review.</b>" % (pending_high, " still awaits" if pending_high == 1 else "s still await")
    s += [Paragraph(summary, BODY), Spacer(1, 8),
          _summary_table(total, by_sev["High"], by_status["Pending"], by_status["Escalated"]), Spacer(1, 8),
          _charts(by_sev, by_status)]

    s.append(Paragraph("2. Top 10 threats", H1))
    head = [Paragraph(h, CELL_HEAD) for h in ["#", "Indicator", "Type", "Score", "Severity", "Tags", "Status"]]
    rows = [head]
    for n, i in enumerate(scored[:10], 1):
        rows.append([Paragraph(str(n), SMALL), Paragraph(_short(i.value), MONO), Paragraph(i.type, SMALL),
                     Paragraph("<b>%d</b>" % i.score, SMALL), _pill(i.severity, SEV_COLOR.get(i.severity, GREY)),
                     Paragraph(", ".join(_tags(i)) or "-", SMALL), _pill(i.status, STATUS_COLOR.get(i.status, GREY))])
    t = Table(rows, colWidths=[8 * mm, 56 * mm, 16 * mm, 13 * mm, 17 * mm, 40 * mm, 24 * mm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                           ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    s.append(t)

    decided = [i for i in scored if i.status != "Pending"]
    s.append(Paragraph("3. Analyst decisions", H1))
    if decided:
        rows = [[Paragraph(h, CELL_HEAD) for h in ["Indicator", "Score", "Decision", "Analyst note"]]]
        for i in decided[:15]:
            rows.append([Paragraph(_short(i.value), MONO), Paragraph(str(i.score), SMALL),
                         _pill(i.status, STATUS_COLOR.get(i.status, GREY)), Paragraph(i.analyst_note or "-", SMALL)])
        t = Table(rows, colWidths=[52 * mm, 14 * mm, 22 * mm, 86 * mm], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                               ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                               ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        s.append(t)
    else:
        s.append(Paragraph("No analyst decisions have been recorded yet.", NOTE))

    recs = _recommendations(scored, by_sev, pending_high)
    block = [Paragraph("4. Recommendations", H1)]
    for n, r in enumerate(recs, 1):
        block.append(Paragraph(r, ParagraphStyle("rec", parent=BODY, leftIndent=14, firstLineIndent=-14, spaceAfter=4),
                               bulletText="%d." % n))
    s.append(KeepTogether(block))

    meth = [Paragraph("5. Methodology and limitations", H1),
            Paragraph("Every indicator receives a weighted score from five factors. The factor breakdown is stored with each indicator, "
                      "so an analyst can always see why a score was given.", BODY), Spacer(1, 6)]
    rows = [[Paragraph(h, CELL_HEAD) for h in ["Factor", "Weight", "What it measures"]]]
    for f, w, d in WEIGHTS:
        rows.append([Paragraph(f, SMALL), Paragraph("<b>%s</b>" % w, SMALL), Paragraph(d, SMALL)])
    t = Table(rows, colWidths=[38 * mm, 18 * mm, 118 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                           ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE), ("TOPPADDING", (0, 0), (-1, -1), 4),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    meth += [t, Spacer(1, 6),
             Paragraph("Limitations: the feed contains no last-seen date, so recency is based on the first-seen date. "
                       "Source reputation and malware severity values are fixed lookup tables and should be tuned to the organisation. "
                       "Scores support, but do not replace, analyst judgement.", NOTE)]
    s.append(KeepTogether(meth))

    doc.build(s, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
