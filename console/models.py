# coding=utf-8
from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import User
# Create your models here.


class Domain(models.Model):
    domain_name = models.CharField(max_length=160)
    domain_id = models.CharField(max_length=80)
    visitor = models.ManyToManyField(User, blank=True, related_name='visit_domain', verbose_name=u"访问者")
    operator = models.ManyToManyField(User, blank=True, related_name='operate_domain', verbose_name=u"操作者")

    def __unicode__(self):
        return self.domain_name

    class Meta:
        db_tablespace = 'domain'


class Record(models.Model):
    domain_id = models.CharField(max_length=80)
    record_id = models.CharField(max_length=80)
    sub_domain = models.CharField(max_length=160)
    record_type = models.CharField(max_length=80)
    record_line = models.CharField(max_length=80)
    value = models.CharField(max_length=160)

    def __unicode__(self):
        return self.record_id

    class Meta:
        db_tablespace = 'domain'


class Line(models.Model):
    linename = models.CharField(max_length=80)

    def __unicode__(self):
        return self.linename

    class Meta:
        db_tablespace = 'line'

