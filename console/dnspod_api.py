import json
import requests
from requests.exceptions import ConnectionError, SSLError, Timeout
from django.contrib.auth.models import User
from django.http import HttpResponse
from rest_framework import viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from dnspod.settings import *


class DnspodMixin(object):

    @staticmethod
    def get_default_headers():
        return {
            "UserAgent": "Dnspod client/0.0.1 (%s)" % DNSPOD_MAIL,
        }

    @staticmethod
    def get_default_data():
        return {
            "login_token": "%s,%s" % (DNSPOD_ID, DNSPOD_TOKEN),
            "format": "json",
            "lang": "cn"
        }
    
    def get_dnspod_response(self, url, data=None, headers=None):
        self.data = data if data else self.get_default_data()
        self.headers = headers if headers else self.get_default_headers()

        try:
            response = requests.post(url, data=self.data, headers=self.headers)
        except (ConnectionError, SSLError):
            return {
                'code': 502,
                'error': 'Bad gateway'
            }
        except (Timeout):
            return {
                'code': 504,
                'error': 'Gateway time out'
            }

        data = response.json()
        return {
            'code': 200,
            'data': data
        }


class DomainList(DnspodMixin, APIView):
    """
    List all domains, or create a new domain.
    """

    def domain_info(self, domain_id, format=None):
        url = "https://dnsapi.cn/Domain.Info"

        data = self.get_default_data()
        data.update({"domain_id": domain_id})

        result = self.get_dnspod_response(url, data)
        status = result['code']

        if status == 200:
            body = result['data']['domain']['name']
        else:
            body = result['data']['status']['message']

        return body

    def get(self, format=None):
        url = "https://dnsapi.cn/Domain.List"
        result = self.get_dnspod_response(url)
        status = result['code']

        if status == 200:
            body = result['data']
        else:
            body = result


        return body['domains']
        # return Response(body, status)

    def post(self, domain, format=None):
        url = "https://dnsapi.cn/Domain.Create"

        data = self.get_default_data()
        data.update({"domain": domain})

        result = self.get_dnspod_response(url, data)
        status = result['code']

        if status == 200:
            body = result['data']
        else:
            body = result

        if status == 200 and body['status']['code'] == "1":
            domain_name = body['domain']['domain']
            domain_id = int(body['domain']['id'])
           # Domain.objects.get_or_create(name=domain_name, domain_id=domain_id)

        #return Response(body, status)
        return body

    def delete(self, domain_id, format=None):
        url = "https://dnsapi.cn/Domain.Remove"

        data = self.get_default_data()
        data.update({"domain_id": domain_id})

        result = self.get_dnspod_response(url, data)
        status = result['code']

        if status == 200:
            body = result['data']
        else:
            body = result

        return body

class DomainDetail(DnspodMixin, APIView):
    """
    Retrieve, update or delete a domain instance.
    """
    def domain_info(self, domain_id, format=None):
        url = "https://dnsapi.cn/Domain.Info"

        data = self.get_default_data()
        data.update({"domain_id": domain_id})

        result = self.get_dnspod_response(url, data)
        status = result['code']

        if status == 200:
            body = result['data']
        else:
            body = result

        return body

    def get_lines(self, domain_id, domain_grade="%s" % DNSPOD_GRADE):
        url = "https://dnsapi.cn/Record.Line"
        data = self.get_default_data()
        data.update({
            "domain_id": domain_id,
            "domain_grade": domain_grade
        })
        # self.headers = self.get_default_headers()

        result = self.get_dnspod_response(url)
        status = result['code']
        data = result['data']
        #print result
		
        if status == 200 :
            #return data['line_ids']
        #else:
            return data['status']['message']

    def get(self, domain_id, format=None):
        url = "https://dnsapi.cn/Record.List"
        
        data = self.get_default_data()
        data.update({"domain_id": domain_id})

        result = self.get_dnspod_response(url, data)
        status = result['code']

        if status == 200:
            body = result['data']
        else:
            body = result

        return body
        #return Response(body, status)

    def post(self, domain_id, sub_domain, record_type, record_line, value, mx='', format=None):
        url = "https://dnsapi.cn/Record.Create"
        #sub_domain = request.data['sub_domain']
        #record_type = request.data['record_type']
        #record_line_id = request.data['record_line_id']
        #value = request.data['value']

        data = self.get_default_data()
        data.update({
            "domain_id": domain_id,
            "sub_domain": sub_domain,
            "record_type": record_type,
            "record_line": record_line,
            "value": value,
            "mx": mx
        })

        result = self.get_dnspod_response(url, data)
        status = result['code']

        if status == 200:
            body = result['data']
        else:
            body = result

        return body

    def put(self, request, domain_id, format=None):
        pass

    def delete(self, request, domain_id, format=None):
        url = "https://dnsapi.cn/Domain.Remove"

        data = self.get_default_data()
        data.update({"domain_id": domain_id})

        result = self.get_dnspod_response(url, data)
        status = result['code']
        data = result['data']

        if status == 200 and data['status']['code'] == "1":

            body = result['data']
        else:
            body = result

        return body

    def batch(self, domain_id, records):
        url = "https://dnsapi.cn/Batch.Record.Create"

        data = self.get_default_data()
        data.update({"domain_id":domain_id, "records":records})

        result = self.get_dnspod_response(url, data)
        status = result['code']
        data = result['data']
        '''
        if status == 200 and data['status']['code'] == '1':
            body = result['data']
        else:
            body = result
        '''
        return result

 

class RecordDetail(DnspodMixin, APIView):
    def get(self, domain_id, record_id, format=None):
        url = "https://dnsapi.cn/Record.Info"

        data = self.get_default_data()
        data.update({
            "domain_id": domain_id,
            "record_id": record_id
        })

        result = self.get_dnspod_response(url, data)
        status = result['code']
        data = result['data']

        if status == 200:
            body = result['data']
        else:
            body = result

        return body

    def delete(self, reqeust, domain_id, record_id, format=None):
        url = "https://dnsapi.cn/Record.Remove"

        data = self.get_default_data()
        data.update({
            "domain_id": domain_id,
            "record_id": record_id
        })

        result = self.get_dnspod_response(url, data)
        status = result['code']
        data = result['data']

        if status == 200:
            body = result['data']
        else:
            body = result

        return body

    def modify(self, domain_id, record_id, sub_domain, record_type, record_line, value, format=None):
        url = "https://dnsapi.cn/Record.Modify"

        data = self.get_default_data()
        data.update({
            "domain_id": domain_id,
            "record_id": record_id,
            "sub_domain": sub_domain,
            "record_type": record_type,
            "record_line": record_line,
            "value": value
		})

        result = self.get_dnspod_response(url, data)
        status = result['code']
        data = result['data']

        if status == 200:
            body = result['data']
        else:
            body = result

        return body

    def batch_modify(self, record_id, change_to, change='value', format=None):
        url = "https://dnsapi.cn/Batch.Record.Modify"

        data = self.get_default_data()
        data.update({
            "record_id": record_id,
            "change": change,
            "change_to": change_to,
        })

        result = self.get_dnspod_response(url, data)
        status = result['code']
        data = result['data']

        if status == 200:
            body = result['data']
        else:
            body = result

        return body
