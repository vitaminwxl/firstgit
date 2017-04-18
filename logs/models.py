# coding=utf-8
from __future__ import unicode_literals

from django.db import models


class Logs(models.Model):
    user = models.CharField(max_length=160)
    domain = models.CharField(max_length=160)
    operation = models.CharField(max_length=160)
    record_type = models.CharField(max_length=160)
    record_name = models.CharField(max_length=160)
    value = models.CharField(max_length=160)
    line = models.CharField(max_length=160)
    date_time = models.DateTimeField(auto_now=True)

    def __unicode__(self):
        return self.domain

    class Meta:
        db_tablespace = 'logs'
