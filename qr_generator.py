import os
from pathlib import Path
import qrcode


def generate_audit_qr(audit_id: str, output_dir: str = "reports") -> str:
    """
    Generate a QR code for a specific audit.

    The QR contains only the audit ID, not the network configuration.
    Saves the generated QR code inside the reports/ directory.
    """
    reports_dir = Path(output_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    qr_data = f"Audit ID: {audit_id}"

    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=4
    )

    qr.add_data(qr_data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    filename = reports_dir / f"{audit_id}_qr.png"
    img.save(filename)

    return str(filename)


if __name__ == "__main__":
    audit_id = input("Enter Audit ID: ")
    qr_file = generate_audit_qr(audit_id)
    print(f"QR generated successfully: {qr_file}")
