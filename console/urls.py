"""dnspod URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin
import views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^list/$', views.domain_show, name='domain_show'),
    url(r'^sync/$', views.domain_sync, name='domain_sync'),
    url(r'^add/$', views.domain_add, name='domain_add'),
    url(r'^appoint/$', views.domain_appoint, name='domain_appoint'),
    url(r'^del/$', views.domain_del, name='domain_del'),
    url(r'^record/list/$', views.record_show, name='record_show'),
    url(r'^record/del/$', views.record_del, name='record_del'),
    url(r'^record/check/$', views.record_check, name='record_check'),
    url(r'^record/rollback/$', views.record_rollback, name='record_rollback'),
    url(r'^record/add/$', views.record_add, name='record_add'),
    url(r'^record/addbatch/$', views.record_add_batch, name='record_add_batch'),
    url(r'^record/edit/$', views.record_edit, name='record_edit'),
]
