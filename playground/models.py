from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     email = db.Column(db.String(120), unique=True, nullable=False)
#     password = db.Column(db.String(256), nullable=False)

class Report(db.Model):
    r_id = db.Column(db.Integer, primary_key=True)
    u_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    saving = db.Column(db.Text, nullable=True)
    withholding = db.Column(db.Text, nullable=True)
    tax_credits = db.Column(db.Text, nullable=True)
    w2_form_data = db.Column(db.Text, nullable=True)
    date = db.Column(db.DateTime, nullable=False)
    plan = db.Column(db.String(10), nullable=True)
    chat_count = db.Column(db.Integer, default=0)
    call_count = db.Column(db.Integer, default=0)