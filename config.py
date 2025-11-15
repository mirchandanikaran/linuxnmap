import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'replace-with-a-secret')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///scans.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
