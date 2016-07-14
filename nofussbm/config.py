from os import getenv


class Config(object):
    MONGODB_URI = getenv('MONGODB_URI')
    SECRET_KEY = getenv('SECRET_KEY')
    SENDGRID_USERNAME = getenv('SENDGRID_USERNAME')
    SENDGRID_PASSWORD = getenv('SENDGRID_PASSWORD')
    SENDGRID_SENDER = getenv('SENDGRID_SENDER', 'Massimo Santini <massimo.santini@gmail.com>')
