from flask import Blueprint, jsonify, request

from models.order import Order, Shipment
from services.shiprocket_service import ShipRocketService
from utils.auth_utils import get_current_user, jwt_required_user
from utils.security import csrf_protect_json


shipping_bp = Blueprint("shipping_routes", __name__, url_prefix="/api/shipping")


@shipping_bp.post("/rates")
@csrf_protect_json
def shipping_rates():
    data = request.get_json() or {}
    pincode = data.get("pincode")
    weight = float(data.get("weight", 0.5))
    if not pincode:
        return jsonify({"error": "Pincode required"}), 400

    base = 80
    surcharge = 40 if str(pincode).startswith("7") else 20
    weight_fee = int(weight * 15)

    return jsonify(
        {
            "pincode": str(pincode),
            "rates": [
                {"partner": "ShipRocket Express", "amount": base + surcharge + weight_fee, "eta_days": 3},
                {"partner": "ShipRocket Standard", "amount": base + weight_fee, "eta_days": 5},
            ],
        }
    )


@shipping_bp.get("/track/<string:tracking_id>")
@jwt_required_user
def track(tracking_id):
    user = get_current_user()
    shipment = Shipment.query.filter_by(tracking_id=tracking_id).first_or_404()
    order = Order.query.filter_by(id=shipment.order_id, user_id=user.id).first()
    if not order and not user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    data = ShipRocketService.track_shipment(tracking_id)
    return jsonify(data)
