import secrets
from datetime import datetime, timedelta
from flask import current_app, url_for
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from models import db, PasswordResetToken

def send_reset_email(user):
    token = secrets.token_urlsafe(32)

    record = PasswordResetToken(
        user_id=user.id,
        token=token,
        expires_at=datetime.utcnow() + timedelta(minutes=30)
    )
    db.session.add(record)
    db.session.commit()

    reset_link = url_for(
        "reset_password",
        token=token,
        _external=True
    )

    message = Mail(
        from_email=current_app.config["FROM_EMAIL"],
        to_emails=user.email,
        subject="Reset your HyperFit password",
        html_content=f"""
        <h3>Password Reset</h3>
        <p>Click the link below to reset your password:</p>
        <a href="{reset_link}">Reset Password</a>
        <p>This link expires in 30 minutes.</p>
        """
    )

    sg = SendGridAPIClient(current_app.config["SENDGRID_API_KEY"])
    sg.send(message)
