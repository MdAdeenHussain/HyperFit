from datetime import datetime

from extensions import db


class AdminActivity(db.Model):
    __tablename__ = "admin_activities"

    id = db.Column(db.Integer, primary_key=True)
    activity_type = db.Column(db.String(64), nullable=False, index=True)
    message = db.Column(db.String(255), nullable=False)
    meta = db.Column("metadata", db.JSON, default=dict, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    user = db.relationship("User")


class CMSPage(db.Model):
    __tablename__ = "cms_pages"

    id = db.Column(db.Integer, primary_key=True)
    page_key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    title = db.Column(db.String(160), nullable=False)
    draft_content = db.Column(db.JSON, default=dict, nullable=False)
    live_content = db.Column(db.JSON, default=dict, nullable=False)
    is_published = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    published_at = db.Column(db.DateTime, nullable=True)

    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    published_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)


class CMSVersion(db.Model):
    __tablename__ = "cms_versions"

    id = db.Column(db.Integer, primary_key=True)
    page_id = db.Column(db.Integer, db.ForeignKey("cms_pages.id"), nullable=False, index=True)
    version_number = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(32), nullable=False, default="draft_update")
    changed_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    change_summary = db.Column(db.JSON, default=dict, nullable=False)
    content = db.Column(db.JSON, default=dict, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    page = db.relationship("CMSPage", backref=db.backref("versions", lazy=True, cascade="all, delete-orphan"))
    user = db.relationship("User")


class SiteSetting(db.Model):
    __tablename__ = "site_settings"

    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(80), unique=True, nullable=False, index=True)
    value = db.Column(db.JSON, default=dict, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    user = db.relationship("User")


class EmailCampaign(db.Model):
    __tablename__ = "email_campaigns"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    campaign_type = db.Column(db.String(40), nullable=False, default="newsletter")
    subject = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(24), nullable=False, default="queued")
    sent_count = db.Column(db.Integer, nullable=False, default=0)
    open_rate = db.Column(db.Float, nullable=False, default=0.0)
    click_rate = db.Column(db.Float, nullable=False, default=0.0)
    conversion_rate = db.Column(db.Float, nullable=False, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    user = db.relationship("User")
