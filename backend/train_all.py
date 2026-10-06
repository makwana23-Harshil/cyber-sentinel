"""
Run from the backend/ directory:
    python train_all.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from detection.sms.train_sms import train as train_sms
from detection.email.train_email import train as train_email
from detection.url.train_url import train as train_url


def train_all():
    print("=" * 55)
    print("CyberSentinel Pro — Training all models")
    print("=" * 55)

    train_sms()
    train_email()
    train_url()

    print("=" * 55)
    print("All models trained and saved to backend/models/")
    print("=" * 55)


if __name__ == '__main__':
    train_all()
