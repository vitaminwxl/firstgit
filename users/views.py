# coding=utf-8
from django.shortcuts import render
from django.shortcuts import render_to_response
from django.http import HttpResponseRedirect,HttpResponse
from django.contrib.auth.models import User
from console.models import Domain
from dnspod.views import *


@require_admin()
def user_show(request):
    users = User.objects.all()
    # return HttpResponse('users/user_list.html')
    return render(request,'users/user_list.html',locals())


@require_admin()
def user_add(request):
    domain_all = Domain.objects.all()
    if request.method == 'POST':
        user_name = request.POST.get('user_name')
        role = request.POST.get('role')
        visit = request.POST.getlist('visit_domain', '')
        operate = request.POST.getlist('operate_domain', '')
        visit_domain = [Domain.objects.get(domain_name=v) for v in visit]
        operate_domain = [Domain.objects.get(domain_name=o) for o in operate]
        print visit_domain
        if User.objects.filter(username=user_name):
            user_error = '该用户已存在'
            return render_to_response('user_add.html', locals())
        add_user = User(username=user_name)
        add_user.save()
        add_user.visit_domain = visit_domain
        add_user.operate_domain = operate_domain
        add_user.save()
        if role == "manager":
            add_user.is_superuser = True
            add_user.save()

        # for domain in visit_domain:
        #    add_user.
        print add_user.visit_domain.all()
            
        response = '/user/list'
        return HttpResponseRedirect(response)
        # print {'user_name':user_name, 'role':role}
    return render(request, 'users/user_add.html', locals())


@require_admin()	
def user_del(request):
    user_id = request.GET.get('id')
    user_target = User.objects.get(id=user_id)
    user_target.delete()
    response = HttpResponseRedirect('/user/list')
    return response


@require_admin()	
def manager_remove(request):
    user_id = request.GET.get('id')
    user_target = User.objects.get(id=user_id)
    user_target.is_superuser = 0
    user_target.save()
    response = HttpResponseRedirect('/user/list')
    return response


@require_admin()	
def manager_appoint(request):
    user_id = request.GET.get('id')
    user_target = User.objects.get(id=user_id)
    user_target.is_superuser = 1
    user_target.save()
    response = HttpResponseRedirect('/user/list')
    return response
