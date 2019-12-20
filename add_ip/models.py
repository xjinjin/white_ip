from django.db import models

# Create your models here.

class Ip(models.Model):
    id = models.AutoField(primary_key=True)
    ip = models.CharField(max_length=20)  # 114.86.0.0/16
