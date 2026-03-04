from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask import current_app


class SendGridService:
    @staticmethod
    def send_email(to_email: str, subject: str, html_content: str):
        api_key = current_app.config.get("SENDGRID_API_KEY")
        from_email = current_app.config.get("SENDGRID_FROM_EMAIL")

        if not api_key or not from_email:
            current_app.logger.info("SendGrid not configured. Simulated email to %s (%s)", to_email, subject)
            return {"simulated": True, "status": "queued"}

        message = Mail(
            from_email=from_email,
            to_emails=to_email,
            subject=subject,
            html_content=html_content,
        )
        client = SendGridAPIClient(api_key)
        response = client.send(message)
        return {"status_code": response.status_code}
