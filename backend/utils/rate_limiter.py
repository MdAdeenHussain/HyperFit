from extensions import limiter


def auth_limit():
    return limiter.limit("10/minute")


def strict_limit():
    return limiter.limit("5/minute")
