import hmac
import hashlib
from decimal import Decimal
import razorpay
from flask import current_app


class RazorpayService:
    @staticmethod
    def _client():
        key = current_app.config.get("RAZORPAY_KEY_ID")
        secret = current_app.config.get("RAZORPAY_KEY_SECRET")
        if not key or not secret:
            return None
        return razorpay.Client(auth=(key, secret))

    @staticmethod
    def create_order(order_number: str, amount: Decimal):
        client = RazorpayService._client()
        amount_paise = int(Decimal(amount) * 100)

        if not client:
            return {
                "id": f"sim_{order_number}",
                "amount": amount_paise,
                "currency": "INR",
            }

        return client.order.create(
            {
                "amount": amount_paise,
                "currency": "INR",
                "receipt": order_number,
                "payment_capture": 1,
            }
        )

    @staticmethod
    def verify_signature(provider_order_id: str, provider_payment_id: str, signature: str) -> bool:
        secret = current_app.config.get("RAZORPAY_KEY_SECRET")
        if not secret:
            return True
        digest = hmac.new(
            secret.encode("utf-8"),
            f"{provider_order_id}|{provider_payment_id}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(digest, signature)
