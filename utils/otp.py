import random
from datetime import datetime, timedelta
from models import db, OTP

def generate_otp():
    return str(random.randint(100000, 999999))

def create_otp(contact, otp_type):
    otp = generate_otp()

    record = OTP(
        contact=contact,
        otp_code=otp,
        otp_type=otp_type,
        expires_at=datetime.utcnow() + timedelta(minutes=5)
    )

    db.session.add(record)
    db.session.commit()

    return otp
