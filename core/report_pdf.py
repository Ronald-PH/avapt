# Install: pip install reportlab
from __future__ import annotations
from pathlib import Path
from datetime import datetime

try:
    from reportlab.lib.pagesizes   import A4
    from reportlab.lib.styles      import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units       import cm
    from reportlab.lib             import colors
    from reportlab.platypus        import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, KeepTogether,
    )
    from reportlab.platypus.flowables import HRFlowable
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

from core.config import VERSION


# ── colour palette (mirrors HTML report) ─────────────────────────────────────
if HAS_REPORTLAB:
    C_BG      = colors.HexColor("#0a0c10")
    C_BG2     = colors.HexColor("#0f1219")
    C_BG3     = colors.HexColor("#161b24")
    C_BORDER  = colors.HexColor("#1e2533")
    C_TEXT    = colors.HexColor("#c9d1e0")
    C_MUTED   = colors.HexColor("#5a6478")
    C_ACCENT  = colors.HexColor("#00d4ff")
    C_AI      = colors.HexColor("#bf5fff")
    C_CRIT    = colors.HexColor("#ff2d55")
    C_HIGH    = colors.HexColor("#ff6b35")
    C_MED     = colors.HexColor("#ffd60a")
    C_LOW     = colors.HexColor("#30d158")
    C_WHITE   = colors.white
    C_BLACK   = colors.black

    SEV_COLOR = {
        "critical": C_CRIT,
        "high":     C_HIGH,
        "medium":   C_MED,
        "low":      C_LOW,
    }


def _sev_color(sev: str):
    return SEV_COLOR.get(sev, C_MUTED) if HAS_REPORTLAB else None


def _make_styles():
    base = getSampleStyleSheet()
    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    return {
        "title":    ps("title",    fontSize=26, textColor=C_WHITE,   fontName="Helvetica-Bold",
                       spaceAfter=4, leading=30),
        "subtitle": ps("subtitle", fontSize=11, textColor=C_ACCENT,  fontName="Helvetica",
                       spaceAfter=14),
        "h1":       ps("h1",       fontSize=14, textColor=C_ACCENT,  fontName="Helvetica-Bold",
                       spaceBefore=18, spaceAfter=8, leading=18),
        "h2":       ps("h2",       fontSize=11, textColor=C_WHITE,   fontName="Helvetica-Bold",
                       spaceBefore=12, spaceAfter=4, leading=14),
        "body":     ps("body",     fontSize=9,  textColor=C_TEXT,    fontName="Helvetica",
                       leading=13, spaceAfter=4),
        "code":     ps("code",     fontSize=8,  textColor=colors.HexColor("#e2b96e"),
                       fontName="Courier", leading=11,
                    #    backColor=colors.HexColor("#0d1117"),
                       borderPadding=(4, 6, 4, 6)),
        "muted":    ps("muted",    fontSize=8,  textColor=C_MUTED,   fontName="Helvetica",
                       leading=11),
        "label":    ps("label",    fontSize=7,  textColor=C_MUTED,   fontName="Helvetica-Bold",
                       leading=9),
    }


def _page_bg(canvas, doc):
    """Draw dark background on every page."""
    canvas.saveState()
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
    # header bar
    canvas.setFillColor(C_BG2)
    canvas.rect(0, A4[1] - 44, A4[0], 44, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 13)
    canvas.setFillColor(C_ACCENT)
    canvas.drawString(cm, A4[1] - 28, "avapt")
    canvas.setFillColor(C_MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(cm, A4[1] - 38, f"v{VERSION}  —  AI Security Report")
    # footer
    canvas.setFillColor(C_BG3)
    canvas.rect(0, 0, A4[0], 28, fill=1, stroke=0)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_MUTED)
    canvas.drawString(cm, 10, f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    canvas.drawRightString(A4[0] - cm, 10, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(result: dict, output_path: str | Path) -> Path:
    """Build a PDF report from scan results. Returns the output path."""
    if not HAS_REPORTLAB:
        raise ImportError(
            "reportlab is required for PDF export.\n"
            "Install with:  pip install reportlab"
        )

    output_path = Path(output_path)
    meta        = result["meta"]
    summary     = result["summary"]
    src_counts  = result.get("source_counts", {})
    findings    = result["findings"]
    total       = len(findings)
    risk        = ("CRITICAL" if summary["critical"] > 0 else
                   "HIGH"     if summary["high"]     > 0 else
                   "MEDIUM"   if summary["medium"]   > 0 else "LOW")

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize      = A4,
        leftMargin    = cm,
        rightMargin   = cm,
        topMargin     = 1.6 * cm,
        bottomMargin  = 1.2 * cm,
        title         = "AVAPT Security Report",
        author        = f"avapt v{VERSION}",
    )

    st    = _make_styles()
    story = []

    # ── cover ─────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1.2 * cm))
    story.append(Paragraph("Security Assessment Report", st["title"]))
    story.append(Paragraph(
        f"Target: {meta['scan_root']}  |  Model: {meta['ai_model']}  |  "
        f"Risk: <font color='#{_hex(SEV_COLOR.get(risk.lower(), C_MUTED))}'>{risk}</font>",
        st["subtitle"],
    ))
    story.append(HRFlowable(width="100%", color=C_BORDER, thickness=1))
    story.append(Spacer(1, 0.4 * cm))

    # ── meta table ────────────────────────────────────────────────────────────
    story.append(Paragraph("Scan Metadata", st["h1"]))
    meta_data = [
        ["Target",        meta["scan_root"]],
        ["Timestamp",     meta["timestamp"]],
        ["Files Scanned", str(meta["files_scanned"])],
        ["Code Files",    str(meta["code_files"])],
        ["Languages",     ", ".join(meta["languages"]) or "N/A"],
        ["AI Model",      meta["ai_model"]],
        ["Ollama URL",    meta["ollama_url"]],
        ["Total Findings",str(total)],
    ]
    meta_tbl = Table(
        [[Paragraph(k, st["label"]), Paragraph(v, st["body"])] for k, v in meta_data],
        colWidths=[3.5 * cm, 14 * cm],
    )
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), C_BG2),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_BG2, C_BG3]),
        ("TEXTCOLOR",   (0, 0), (-1, -1), C_TEXT),
        ("GRID",        (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",(0, 0), (-1, -1), 6),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0,0), (-1, -1), 4),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 0.5 * cm))

    # ── summary cards ─────────────────────────────────────────────────────────
    story.append(Paragraph("Risk Summary", st["h1"]))
    card_data = [[
        _card_cell(summary["critical"], "CRITICAL", C_CRIT, st),
        _card_cell(summary["high"],     "HIGH",     C_HIGH, st),
        _card_cell(summary["medium"],   "MEDIUM",   C_MED,  st),
        _card_cell(summary["low"],      "LOW",      C_LOW,  st),
    ]]
    card_tbl = Table(card_data, colWidths=[4.4 * cm] * 4)
    card_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), C_BG2),
        ("BOX",          (0, 0), (0, 0), 1, C_CRIT),
        ("BOX",          (1, 0), (1, 0), 1, C_HIGH),
        ("BOX",          (2, 0), (2, 0), 1, C_MED),
        ("BOX",          (3, 0), (3, 0), 1, C_LOW),
        ("TOPPADDING",   (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(card_tbl)
    story.append(Spacer(1, 0.5 * cm))

    # ── source summary ────────────────────────────────────────────────────────
    src_data = [[
        Paragraph(f"<font color='#{_hex(C_AI)}'>{src_counts.get('ai', 0)}</font>"
                  f"  <font color='#{_hex(C_MUTED)}'>AI Findings</font>", st["h2"]),
        Paragraph(f"<font color='#{_hex(C_MED)}'>{src_counts.get('dependency', 0)}</font>"
                  f"  <font color='#{_hex(C_MUTED)}'>Dependency CVEs</font>", st["h2"]),
    ]]
    src_tbl = Table(src_data, colWidths=[9 * cm, 9 * cm])
    src_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_BG3),
        ("GRID",       (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",(0, 0), (-1, -1), 10),
    ]))
    story.append(src_tbl)
    story.append(Spacer(1, 0.5 * cm))

    # ── executive summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", st["h1"]))
    story.append(Paragraph(
        f"Assessment of <b>{meta['scan_root']}</b> using "
        f"<font color='#{_hex(C_AI)}'>{meta['ai_model']}</font> via Ollama. "
        f"{meta['code_files']} code file(s) "
        f"({', '.join(meta['languages']) or 'unknown'}) were analysed in full — "
        f"the complete source of each file was sent to the AI for semantic reasoning. "
        f"Overall risk posture: "
        f"<font color='#{_hex(SEV_COLOR.get(risk.lower(), C_MUTED))}'><b>{risk}</b></font>.",
        st["body"],
    ))
    story.append(Spacer(1, 0.4 * cm))

    # ── findings table ────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph(f"Detailed Findings ({total})", st["h1"]))

    tbl_header = ["#", "Vulnerability", "Severity", "Score", "File", "CWE", "Conf"]
    tbl_rows   = [
        [Paragraph(h, st["label"]) for h in tbl_header]
    ]
    for idx, f in enumerate(findings, 1):
        sc  = SEV_COLOR.get(f["severity"], C_MUTED)
        row = [
            Paragraph(str(idx), st["muted"]),
            Paragraph(f['type'][:50], st["body"]),
            Paragraph(
                f"<font color='#{_hex(sc)}'>{f['severity'].upper()}</font>",
                st["body"],
            ),
            Paragraph(
                f"<font color='#{_hex(sc)}'>{f['severity_score']}</font>",
                st["body"],
            ),
            Paragraph(Path(f['file']).name[:30], st["muted"]),
            Paragraph(f.get('cwe', ''), st["muted"]),
            Paragraph(f.get('confidence', ''), st["muted"]),
        ]
        tbl_rows.append(row)

    col_w = [0.8*cm, 5.5*cm, 2*cm, 1.5*cm, 3.5*cm, 2.5*cm, 1.8*cm]
    findings_tbl = Table(tbl_rows, colWidths=col_w, repeatRows=1)
    findings_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_BG3),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_BG2, C_BG3]),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(findings_tbl)

    # ── individual finding details ────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Finding Details", st["h1"]))

    for idx, f in enumerate(findings, 1):
        sc = SEV_COLOR.get(f["severity"], C_MUTED)
        ap = f.get("attack_path", {})

        block = []
        block.append(Paragraph(
            f"<font color='#{_hex(sc)}'>[{f['severity'].upper()}]</font>  "
            f"<b>{f['type']}</b>  "
            f"<font color='#{_hex(C_MUTED)}'>#{idx}</font>",
            st["h2"],
        ))
        block.append(HRFlowable(width="100%", color=C_BORDER, thickness=0))

        # detail grid
        detail_rows = [
            ["File",       f["file"]],
            ["Lines",      f"{f['location']['from_line']} – {f['location']['to_line']}"],
            ["Language",   f["code"].get("language", "")],
            ["CWE",        f.get("cwe", "")],
            ["CVE",        str(f.get("cve_id") or "N/A")],
            ["Confidence", f.get("confidence", "")],
            ["Source",     f.get("source", "ai").upper()],
        ]
        detail_tbl = Table(
            [[Paragraph(k, st["label"]), Paragraph(v, st["body"])]
             for k, v in detail_rows],
            colWidths=[2.8 * cm, 14.7 * cm],
        )
        detail_tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), C_BG3),
            ("GRID",         (0, 0), (-1, -1), 0.4, C_BORDER),
            ("LEFTPADDING",  (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING",   (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ]))
        block.append(detail_tbl)
        block.append(Spacer(1, 0.2 * cm))

        # explanation
        if f.get("explanation"):
            block.append(Paragraph("Explanation", st["label"]))
            block.append(Paragraph(f["explanation"], st["body"]))
            block.append(Spacer(1, 0.15 * cm))

        # attack path
        if ap:
            block.append(Paragraph("Attack Path", st["label"]))
            block.append(Paragraph(
                f"Entry: {ap.get('entry_point', '')}  |  "
                f"Impact: {ap.get('impact', '')}  |  "
                f"Likelihood: {ap.get('likelihood', '')}",
                st["body"],
            ))
            prereqs = ap.get("prerequisites", [])
            if prereqs:
                block.append(Paragraph(
                    "Prerequisites: " + "; ".join(prereqs), st["muted"]
                ))
            block.append(Spacer(1, 0.15 * cm))

        # remediation
        if f.get("remediation"):
            block.append(Paragraph("Remediation", st["label"]))
            block.append(Paragraph(f["remediation"], st["body"]))
            block.append(Spacer(1, 0.15 * cm))

        # code snippet
        snippet = f["code"].get("snippet", "").strip()
        if snippet:
            block.append(Paragraph("Code Snippet", st["label"]))
            # truncate long snippets
            lines = snippet.splitlines()[:20]
            if len(snippet.splitlines()) > 20:
                lines.append("... (truncated)")
            block.append(Paragraph(
                "\n".join(lines).replace("&","&amp;").replace("<","&lt;"),
                st["code"],
            ))

        block.append(Spacer(3, 0.4 * cm))
        story.append(KeepTogether(block))

    doc.build(story, onFirstPage=_page_bg, onLaterPages=_page_bg)
    return output_path


# ── internal helpers ──────────────────────────────────────────────────────────

def _hex(color) -> str:
    """reportlab color → hex string (without #)."""
    try:
        r = int(color.red   * 255)
        g = int(color.green * 255)
        b = int(color.blue  * 255)
        return f"{r:02x}{g:02x}{b:02x}"
    except Exception:
        return "888888"


def _card_cell(count: int, label: str, color, styles: dict):
    from reportlab.platypus import Table as _T
    inner = _T(
        [[Paragraph(f"<font color='#{_hex(color)}'>{count}</font>", styles["title"])],
         [Paragraph(label, styles["label"])]],
        colWidths=[4 * cm],
    )
    inner.setStyle(TableStyle([
        ("ALIGN",     (0,0),(-1,-1),"CENTER"),
        ("VALIGN",    (0,0),(-1,-1),"MIDDLE"),
        ("TOPPADDING",(0,0),(-1,-1),0),
        ("BOTTOMPADDING",(0,0),(-1,-1),0),
    ]))
    return inner
