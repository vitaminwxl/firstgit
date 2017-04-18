# coding-utf-8
from django.shortcuts import render
from django.http import HttpResponseRedirect,HttpResponse
from logs.models import *
from dnspod.views import require_admin


@require_admin()
def logs_show(request):
    logs = Logs.objects.all()
    return render(request, 'logs/logs_show.html', locals())
