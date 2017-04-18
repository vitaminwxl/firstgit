# coding=utf-8
import xlrd
import re
from django.shortcuts import render
from django.http import HttpResponseRedirect,HttpResponse
from django.contrib.auth.decorators import login_required
import dns.resolver
from django.contrib.auth.models import User
from models import Domain, Record, Line
from django.db.models import Q
from dnspod.views import *
from dnspod_api import *


@login_required()
def domain_show(request):
    domain_obj = Domain.objects.all()
    error = request.GET.get('error')
    return render(request,'domain/domain_show.html',locals())


@require_admin()
def domain_sync(request):
    domain_list = DomainList()
    domain_all_info = domain_list.get()
    
    for domain_info in domain_all_info:
        if not Domain.objects.filter(domain_name=domain_info['name']):
            domain_add = Domain(domain_name=domain_info['name'], domain_id=domain_info['id'])
            domain_add.save()
    domain_first = Domain.objects.all()[0]
    domain_id = domain_first.domain_id
    domaindetail = DomainDetail()
    lines = domaindetail.get_lines(domain_id)
    if isinstance(lines, list):
        line_all = lines
    else:
        line_all = ['默认']
    for line in line_all:
        if not Line.objects.filter(linename=line):
            line_add = Line(linename=line)
            line_add.save()

    response = '/domain/list'
    return HttpResponseRedirect(response)


@require_admin()
def domain_add(request):
    users = User.objects.all()
    if request.method == 'POST':
        domain_name = request.POST.get('domain_name')
        visitors = request.POST.getlist('visitors', '')
        operators = request.POST.getlist('operators', '')
        domain_list = DomainList()
        domain_add_result = domain_list.post(domain_name)
        if domain_add_result['status']['code'] == '1':
            domain_add_sql = Domain(domain_name=domain_add_result['domain']['domain'],
                                    domain_id=domain_add_result['domain']['id'])
            domain_add_sql.save()
            change_user(domain_name, 'visitor', visitors)
            change_user(domain_name, 'operator', operators)
            set_log(request.user, domain_name, 'add_domain', '-', '-', '-', '-')
            response = '/domain/list'
            return HttpResponseRedirect(response)
        else:
            error = domain_add_result['status']['message']

    return render(request, 'domain/domain_add.html', locals())


@require_admin()
def domain_appoint(request):
    users = User.objects.all()
    domain_id = request.GET.get('id')
    domain = Domain.objects.get(id=domain_id)
    if request.method == 'POST':
        visitors = request.POST.getlist('visitors', '')
        change_user(domain, 'visitor', visitors)
        operators = request.POST.getlist('operators', '')
        change_user(domain, 'operator', operators)
        response = '/domain/list'
        return HttpResponseRedirect(response)
    return render(request, 'domain/domain_appoint.html', locals())


@login_required()
def domain_del(request):
    result = {'status': False, 'error': ''}
    domain_id = request.POST.get('domain_id')
    domain_list = DomainList()
    domain_name = Domain.objects.get(domain_id=domain_id).domain_name
    domain_del_result = domain_list.delete(domain_id)
    if domain_del_result['status']['code'] != '1':
        result['error'] = domain_del_result['status']['message']
    else:
        Domain.objects.filter(domain_id=domain_id).delete()
        set_log(request.user, domain_name, 'del_domain', '-', '-', '-', '-')
        result['status'] = True
    
    return HttpResponse(json.dumps(result))


@login_required()
def record_show(request):
    types = ['A', 'NS', 'MX', 'CNAME']
    lines = Line.objects.all()
    user = request.user
    domain_id = request.GET.get('id')
    domain_name = Domain.objects.get(domain_id=domain_id)
    check_result = check_domain_role(user, domain_id)
    if check_result == '0':
        error = u'没有此域名访问权限'
        response = "/domain/list?error=%s" % error
        return HttpResponseRedirect(response)
    
    domain_list = DomainDetail()
    result = domain_list.get(domain_id)
    records = result['records']

    return render(request, 'domain/record_show.html', locals())


@login_required()
def record_del(request):
    result = {'status': False, 'error': ''}
    record_id = request.POST.get('record_id')
    domain_id = request.POST.get('domain_id')
    domain_name = Domain.objects.get(domain_id=domain_id).domain_name
    record_detail = RecordDetail()
    record_info = record_detail.get(domain_id, record_id)['record']
    record_delete = record_detail.delete(request, domain_id, record_id)
    if record_delete['status']['code'] != '1':
        result['error'] = record_delete['status']['message']
    else:
        set_log(request.user, domain_name, 'del_record', record_info['record_type'],
                record_info['sub_domain'], record_info['value'], record_info['record_line'])
        result['status'] = True
    return HttpResponse(json.dumps(result))


@login_required()
def record_check(request):
    result = {'status': False, 'error': ''}
    record_id = request.POST.get('record_id')
    domain_id = request.POST.get('domain_id')
    record_detail = RecordDetail()
    record_check = record_detail.get(domain_id, record_id)['record']
    domain_name = Domain.objects.get(domain_id=domain_id).domain_name
    sub_domain = record_check['sub_domain']
    record_type = record_check['record_type']
    value = record_check['value']
    check_result = check_record(domain_name, sub_domain, record_type, value)
    if check_result != 'success':
        result['error'] = check_result
    else:
        result['status'] = True
    return HttpResponse(json.dumps(result))


@login_required()
def record_rollback(request):
    result = {'status': False, 'error': ''}
    record_id_old = request.POST.get('record_id')
    domain_id_old = request.POST.get('domain_id')
    domain_name = Domain.objects.get(domain_id=domain_id_old).domain_name
    if Record.objects.filter(Q(record_id=record_id_old), Q(domain_id=domain_id_old)):
        # 获取oldvalue，
        record_old = Record.objects.get(Q(record_id=record_id_old), Q(domain_id=domain_id_old))
        sub_domain_old = record_old.sub_domain
        record_type_old = record_old.record_type
        line_old = record_old.record_line
        value_old = record_old.value
        record_detail = RecordDetail()
        record_back = record_detail.modify(domain_id_old, record_id_old, sub_domain_old, record_type_old, line_old, value_old)
        if record_back['status']['code'] != '1':
            result['error'] = record_back['status']['message'].encode('utf-8')
        else:
            set_log(request.user, domain_name, 'rollback_record', record_type_old, sub_domain_old, value_old, line_old)
            result['status'] = True
    else:
        result['error'] = '没有回滚方案'

    return HttpResponse(json.dumps(result))


@login_required()
def record_add(request):
    result = {'status': False, 'error': ''}
    domain_id = request.POST.get('domain_id')
    domain_name = Domain.objects.get(domain_id=domain_id).domain_name
    entry_name = request.POST.get('entry_name')
    entry_type = request.POST.get('entry_type')
    entry_line = request.POST.get('entry_line')
    entry_value = request.POST.get('entry_value')
    entry_mx = request.POST.get('entry_mx')
    entry_weight = request.POST.get('entry_weight')
    entry_ttl = request.POST.get('entry_ttl')
    domain_detail = DomainDetail()
    if entry_line == 'all':
        lines_obj = Line.objects.all()
        lines = [l.linename for l in lines_obj]
        for line in lines:
            record_add = domain_detail.post(domain_id, entry_name, entry_type, line, entry_value, entry_mx)
            if record_add['status']['code'] != '1':
                result['error'] = record_add['status']['message'].encode('utf-8')
                return HttpResponse(json.dumps(result))
            else:
                set_log(request.user, domain_name, 'add_record', entry_type, entry_name, entry_value, entry_line)
        result['status'] = True
    else:
        record_add = domain_detail.post(domain_id, entry_name, entry_type, entry_line, entry_value, entry_mx)
        if record_add['status']['code'] != '1':
            result['error'] = record_add['status']['message'].encode('utf-8')
        else:
            set_log(request.user, domain_name, 'add_record', entry_type, entry_name, entry_value, entry_line)
            result['status'] = True
    return HttpResponse(json.dumps(result))


@login_required()
def record_add_batch(request):
    if request.method == 'POST':

        domain_id = request.GET.get('id')
        excel_file = request.FILES.get('file_name', '')
        ret = excel_to_db(request, domain_id, excel_file)
        if ret == 'success':
            smg = u'批量操作成功'
        else:
            emg = ret
        
    return render(request, 'domain/record_add_batch.html', locals())


@login_required()
def record_edit(request):
    result = {'status': False, 'error': ''}
    domain_id = request.POST.get('domain_id')
    domain_name = Domain.objects.get(domain_id=domain_id).domain_name
    # record_id = request.POST.get('entry_id')
    sub_domain = request.POST.get('entry_name')
    record_type = request.POST.get('entry_type')
    value = request.POST.get('entry_value')
    line = request.POST.get('entry_line')
    if line != 'all':
        record_id = get_record_id(domain_id, sub_domain, line, record_type)
        if record_id.startswith('error'):
            result['error'] = record_id
        else:
            record_detail = RecordDetail()
            record_info_old = record_detail.get(domain_id, record_id)['record']
            domain_id_old = record_info_old['domain_id']
            record_id_old = record_info_old['id']
            sub_domain_old = record_info_old['sub_domain']
            record_type_old = record_info_old['record_type']
            line_old = record_info_old['record_line']
            value_old = record_info_old['value']
    # record_id = get_record_id(domain_id, sub_domain, line, record_type)
    # if record_id.startswith('error'):
    #    result['error'] = record_id
            record_modify = record_detail.modify(domain_id, record_id, sub_domain, record_type, line, value)
            if record_modify['status']['code'] != '1':
                result['error'] = record_modify['status']['message'].encode('utf-8')
            else:
                set_backup(record_id_old, domain_id_old, sub_domain_old, record_type_old, line_old, value_old)
                set_log(request.user, domain_name, 'edit_record', record_type, sub_domain, value, line)
                result['status'] = True
    else:
        #
        # 批量修改
        lines_obj = Line.objects.all()
        lines = [l.linename for l in lines_obj]
        record_id_all = ""
        record_old_list = []
        for line in lines:
            record_id = get_record_id(domain_id, sub_domain, line, record_type)
            if record_id.startswith('error'):
                result['error'] = record_id
                return HttpResponse(json.dumps(result))
            else:
                record_id_all = record_id_all + record_id + ','
                record_detail = RecordDetail()
                record_info_old = record_detail.get(domain_id, record_id)['record']
                record_info = {
                    "record_id": record_id,
                    "record_line": record_info_old["record_line"],
                    "record_value": record_info_old["value"]
                }
                record_old_list.append(record_info)
        record_id_all.rstrip(',')
        recorddetail = RecordDetail()
        record_batchmodify = recorddetail.batch_modify(record_id_all, value)
        if record_batchmodify['status']['code'] != '1':
            result['error'] = record_batchmodify['status']['message'].encode('utf-8')
        else:
            for record_old in record_old_list:
                
                set_backup(record_old["record_id"], domain_id, sub_domain, record_type, record_old["record_line"],
                           record_old["record_value"])
                set_log(request.user, domain_name, 'edit_record', record_type, sub_domain,
                        value, record_old["record_line"])
            result['status'] = True

    return HttpResponse(json.dumps(result))


def set_backup(record_id_old, domain_id_old, sub_domain_old, record_type_old, line_old, value_old):
    if not Record.objects.filter(record_id=record_id_old):
        record = Record(domain_id=domain_id_old, record_id=record_id_old, sub_domain=sub_domain_old,
                        record_type=record_type_old, record_line=line_old, value=value_old)
        record.save()
    else:
        Record.objects.filter(record_id=record_id_old).update(sub_domain=sub_domain_old,
                                                              record_type=record_type_old,
                                                              record_line=line_old, value=value_old)


def check_record(domain, sub_domain, record_type, value):
    record_name = sub_domain + '.' + domain
    check_list = []
    # error = ''
    try:
        if record_type == 'NS':
            result = dns.resolver.query(domain, record_type)
            for i in result.response.answer:
                for j in i.items:
                    check_list.append(j.to_text())
        elif record_type == 'MX':
            result = dns.resolver.query(domain, record_type)
            for i in result:
                check_list.append(str(i.exchanger))
        else:
            if sub_domain == '@':
                record_name = domain
            result = dns.resolver.query(record_name, record_type)
            for i in result.response.answer:
                for j in i.items:
                    check_list.append(str(j.to_text()))
    except:
        error = '记录格式有误'
        return error
    if value in check_list:
        return 'success'
    else:
        error = '记录校验值错误'
        return error


def change_user(domain, user_type, user_list):
    domain_info = Domain.objects.get(domain_name=domain)
    user_new_list = [User.objects.get(username=name) for name in user_list]
    user_old_list = []
    if user_type == 'visitor':
        user_old_list = domain_info.visitor.all()
    elif user_type == 'operator':
        user_old_list = domain_info.operator.all()
    user_add = set(user_new_list) - set(user_old_list)
    
    user_remove = set(user_old_list) - set(user_new_list)

    for user in user_add:
        if user_type == 'visitor':
            domain_info.visitor.add(user)
        elif user_type == 'operator':
            domain_info.operator.add(user)
    for user in user_remove:
        if user_type == 'visitor':
            domain_info.visitor.remove(user)
        elif user_type == 'operator':
            domain_info.operator.remove(user)
    domain_info.save()


def excel_to_db(request, domain_id, excel_file):
    result = 'success'
    lines_obj = Line.objects.all()
    lines = [l.linename for l in lines_obj]
    try:
        data = xlrd.open_workbook(filename=None, file_contents=excel_file.read())
    except Exception, e:
        return e
    else:
        domain_name = Domain.objects.get(domain_id=domain_id).domain_name
        table = data.sheets()[0]
        rows = table.nrows
        record_lists = []
        for row_num in range(1, rows):
            row = table.row_values(row_num)
            if row:
                sub_domain, record_type, value, record_line, ttl, weight, mx = row
                if sub_domain == '' or record_type == '' or value == '':
                    result = '必填项不能为空'
                    return result
                if record_type not in ['A', 'CNAME', 'MX', 'NS']:
                    result = '记录类型不正确'
                    return result
                # if value 正则不匹配ip类型return '记录值不正确'
                p = re.compile("^((?:(2[0-4]\d)|(25[0-5])|([01]?\d\d?))\.){3}(?:(2[0-4]\d)|(255[0-5])|([01]?\d\d?))$")
                if not p.match(value):
                    result = '记录值不正确'
                    return result
                if record_line not in lines:
                    result = '线路不存在'
                    return result
                ttl = '600' if ttl == '' else ttl
                mx = '' if record_type != 'MX' else mx
                record_line = '默认' if record_line == '' else record_line
                data = {
                    "sub_domain": str(sub_domain),
                    "record_type": str(record_type),
                    "record_line": str(record_line.encode('utf-8')),
                    "value": str(value),
                    "ttl": str(int(ttl)),
                    "MX": str(mx)
                }
                set_log(request.user, domain_name, 'add_record', str(record_type), str(sub_domain),
                        str(value), str(record_line.encode('utf-8')))
                record_lists.append(data)
        record_list = json.dumps(record_lists)
        domain_detail = DomainDetail()
        batch = domain_detail.batch(domain_id, record_list)
        if batch['code'] != 200:
            result = batch['data']
        else:
            if batch['data']['status']['code'] != '1':
                result = batch['data']['status']['message']
    return result


def get_record_id(domain_id, record_name, record_line, record_type):
    domain_list = DomainDetail()
    result = domain_list.get(domain_id)
    records = result['records']
    for record in records:
        if record["name"] == record_name and record["line"] == record_line and record["type"] == record_type:
            return record["id"]
        
    return "error,没有该路线%s的记录" % record_line.encode('utf-8')
