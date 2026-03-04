def order_confirmation_template(name: str, order_number: str, total: float) -> str:
    return f"""
    <h2>Thanks for shopping with HyperFit</h2>
    <p>Hello {name},</p>
    <p>Your order <strong>{order_number}</strong> has been placed successfully.</p>
    <p>Total Amount: <strong>INR {total:.2f}</strong></p>
    <p>We will notify you once shipped.</p>
    """


def newsletter_template(title: str, content: str) -> str:
    return f"""
    <h2>{title}</h2>
    <p>{content}</p>
    <p>- Team HyperFit</p>
    """


def abandoned_cart_template(name: str) -> str:
    return f"""
    <h2>Your HyperFit Cart Misses You</h2>
    <p>Hey {name}, complete your look before your favorites sell out.</p>
    """
