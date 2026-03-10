from extensions import db
from models.newsletter import NewsletterSubscriber
from models.user import User


def normalize_newsletter_email(email: str | None) -> str:
    return (email or "").strip().lower()


def ensure_user_newsletter_subscription(user: User | None):
    if not user or not user.email or user.newsletter_subscribed is False:
        return None, False, False

    email = normalize_newsletter_email(user.email)
    subscriber = NewsletterSubscriber.query.filter_by(email=email).first()
    if subscriber and subscriber.subscribed:
        return subscriber, False, True

    if not subscriber:
        subscriber = NewsletterSubscriber(email=email, subscribed=True)
        db.session.add(subscriber)
        return subscriber, True, False

    subscriber.subscribed = True
    return subscriber, True, False


def set_newsletter_subscription(email: str | None, subscribed: bool, user: User | None = None):
    normalized = normalize_newsletter_email(email)
    if not normalized:
        return None, False, False

    subscriber = NewsletterSubscriber.query.filter_by(email=normalized).first()
    was_subscribed = bool(subscriber and subscriber.subscribed)
    changed = False

    if not subscriber:
        subscriber = NewsletterSubscriber(email=normalized, subscribed=bool(subscribed))
        db.session.add(subscriber)
        changed = True
    elif subscriber.subscribed != bool(subscribed):
        subscriber.subscribed = bool(subscribed)
        changed = True

    linked_user = user or User.query.filter_by(email=normalized).first()
    if linked_user and linked_user.newsletter_subscribed != bool(subscribed):
        linked_user.newsletter_subscribed = bool(subscribed)
        changed = True

    return subscriber, changed, was_subscribed
