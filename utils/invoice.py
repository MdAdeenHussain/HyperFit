from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from datetime import datetime
import os

def generate_invoice(order):
    invoice_dir = "static/invoices"
    os.makedirs(invoice_dir, exist_ok=True)

    filename = f"invoice_{order.id}.pdf"
    path = os.path.join(invoice_dir, filename)

    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    # Header
    elements.append(Paragraph("<b>HYPERFIT</b>", styles["Title"]))
    elements.append(Paragraph("Strength Meets Style", styles["Normal"]))
    elements.append(Paragraph("<br/>", styles["Normal"]))

    # Order info
    elements.append(Paragraph(f"<b>Order ID:</b> {order.id}", styles["Normal"]))
    elements.append(Paragraph(
        f"<b>Date:</b> {order.created_at.strftime('%d %b %Y')}", styles["Normal"]
    ))
    elements.append(Paragraph(
        f"<b>Payment:</b> {order.payment_method}", styles["Normal"]
    ))
    elements.append(Paragraph("<br/>", styles["Normal"]))

    # Address
    elements.append(Paragraph("<b>Delivery Address</b>", styles["Heading3"]))
    elements.append(Paragraph(order.address, styles["Normal"]))
    elements.append(Paragraph("<br/>", styles["Normal"]))

    # Items table
    data = [
        ["Product", "Size", "Qty", "Price", "Subtotal"]
    ]

    for item in order.items:
        data.append([
            item.product_name,
            item.size,
            str(item.quantity),
            f"₹{item.price}",
            f"₹{item.price * item.quantity}"
        ])

    table = Table(data, colWidths=[150, 50, 40, 60, 60])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.black),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("ALIGN", (2, 1), (-1, -1), "CENTER"),
    ]))

    elements.append(table)
    elements.append(Paragraph("<br/>", styles["Normal"]))

    # Total
    elements.append(Paragraph(
        f"<b>Total Amount:</b> ₹{order.total_amount}", styles["Heading2"]
    ))

    doc.build(elements)

    return filename
