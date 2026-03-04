from datetime import datetime, timedelta
import requests
from flask import current_app


class ShipRocketService:
    _token = None

    @staticmethod
    def _auth_headers():
        email = current_app.config.get("SHIPROCKET_EMAIL")
        password = current_app.config.get("SHIPROCKET_PASSWORD")
        if not email or not password:
            return None

        if not ShipRocketService._token:
            response = requests.post(
                "https://apiv2.shiprocket.in/v1/external/auth/login",
                json={"email": email, "password": password},
                timeout=10,
            )
            response.raise_for_status()
            ShipRocketService._token = response.json().get("token")

        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {ShipRocketService._token}",
        }

    @staticmethod
    def create_shipment(order):
        headers = ShipRocketService._auth_headers()
        if not headers:
            return {
                "tracking_id": f"TRK{order.id:06d}",
                "tracking_url": f"https://tracking.hyperfit.local/{order.id}",
                "label_url": None,
                "estimated_delivery": (datetime.utcnow() + timedelta(days=5)).isoformat(),
            }

        payload = {
            "order_id": order.order_number,
            "order_date": order.created_at.strftime("%Y-%m-%d %H:%M"),
            "pickup_location": "primary",
            "billing_customer_name": order.user.full_name,
            "billing_address": order.address.line1,
            "billing_city": order.address.city,
            "billing_pincode": order.address.pincode,
            "billing_state": order.address.state,
            "billing_country": order.address.country,
            "billing_email": order.user.email,
            "billing_phone": order.address.phone,
            "shipping_is_billing": True,
            "order_items": [
                {
                    "name": item.product.name,
                    "sku": item.product.sku,
                    "units": item.quantity,
                    "selling_price": float(item.unit_price),
                }
                for item in order.items
            ],
            "payment_method": "Prepaid",
            "sub_total": float(order.total_amount),
            "length": 18,
            "breadth": 12,
            "height": 4,
            "weight": 0.5,
        }

        response = requests.post(
            "https://apiv2.shiprocket.in/v1/external/orders/create/adhoc",
            headers=headers,
            json=payload,
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        shipment_id = data.get("shipment_id")
        return {
            "tracking_id": str(shipment_id),
            "tracking_url": data.get("awb_code"),
            "label_url": None,
            "estimated_delivery": (datetime.utcnow() + timedelta(days=5)).isoformat(),
        }

    @staticmethod
    def track_shipment(tracking_id: str):
        headers = ShipRocketService._auth_headers()
        if not headers:
            return {"status": "in_transit", "tracking_id": tracking_id}

        response = requests.get(
            f"https://apiv2.shiprocket.in/v1/external/courier/track/shipment/{tracking_id}",
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        return data
