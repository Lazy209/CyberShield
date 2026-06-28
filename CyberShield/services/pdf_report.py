"""Generate PDF security scan reports."""

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_scan_report(scan_data: dict, username: str) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Heading1"], fontSize=18, spaceAfter=12)
    heading = ParagraphStyle("Heading", parent=styles["Heading2"], fontSize=13, spaceAfter=8)
    body = styles["Normal"]

    elements = [
        Paragraph("CyberShield Security Report", title_style),
        Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", body),
        Paragraph(f"User: {username}", body),
        Paragraph(f"Module: {scan_data.get('module', 'N/A')}", body),
        Spacer(1, 0.2 * inch),
        Paragraph("Scan Summary", heading),
        Paragraph(scan_data.get("input_summary", "N/A"), body),
        Spacer(1, 0.1 * inch),
    ]

    result = scan_data.get("result", scan_data)
    if isinstance(result, dict):
        summary = result.get("summary", "No summary available")
        risk = result.get("risk_level", "unknown")
        elements.append(Paragraph(f"Risk Level: <b>{risk.upper()}</b>", body))
        elements.append(Paragraph(summary, body))
        elements.append(Spacer(1, 0.15 * inch))

        findings = result.get("findings", [])
        if findings:
            elements.append(Paragraph("Detailed Findings", heading))
            table_data = [["Severity", "Title", "Detail"]]
            for f in findings[:20]:
                table_data.append([
                    f.get("severity", ""),
                    f.get("title", "")[:40],
                    f.get("detail", "")[:80],
                ])
            table = Table(table_data, colWidths=[0.9 * inch, 1.5 * inch, 3.6 * inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ]))
            elements.append(table)

    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph(
        "<i>CyberShield — AI-Powered Cybersecurity Threat Detection Platform</i>",
        ParagraphStyle("Footer", parent=body, fontSize=8, textColor=colors.grey),
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer.read()
