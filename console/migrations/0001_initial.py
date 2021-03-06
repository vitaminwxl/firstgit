# -*- coding: utf-8 -*-
# Generated by Django 1.10.5 on 2017-02-14 11:07
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Domain',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain_name', models.CharField(max_length=160)),
                ('domain_id', models.CharField(max_length=80)),
                ('operator', models.ManyToManyField(blank=True, related_name='operate_domain', to=settings.AUTH_USER_MODEL, verbose_name='\u64cd\u4f5c\u8005')),
                ('visitor', models.ManyToManyField(blank=True, related_name='visit_domain', to=settings.AUTH_USER_MODEL, verbose_name='\u8bbf\u95ee\u8005')),
            ],
            options={
                'db_tablespace': 'domain',
            },
        ),
    ]
