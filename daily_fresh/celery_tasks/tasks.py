from celery import Celery

import os,django

from django.core.mail import send_mail

'''为celery配置django环境'''
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "daily_fresh.settings")
django.setup()

'''broker为中间者用来存储任务'''
app = Celery('celery_tasks.tasks', broker='redis://192.168.12.223:6379/3')

@app.task
def tasks_send_mail(subject, message, sender, receiver, html_message):
    send_mail(subject, message, sender, receiver, html_message=html_message)