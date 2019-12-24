from django.shortcuts import render

# Create your views here.
from django.shortcuts import HttpResponse
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework.views import APIView
import iptc
from add_ip.models import Ip
import os
import subprocess
import time

class add_white_ip(APIView):

    def get(self, request):

        # http://192.168.1.240:8001/add_ip/?ip=114.87.177.174
        # print(request.query_params) # <QueryDict: {'ip': ['192.168.1.240'], 'name': ['abc']}>
        # print(type(request.query_params))   # <class 'django.http.request.QueryDict'>
        # print(request.query_params.get('ip',''))    # 192.168.1.240
        # print(type(request.query_params.get('ip','')))     # <class 'str'>
        ip = request.query_params.get('ip','')

        if ip:

            ip_list = ip.split('.', 2)  # ['192', '168', '1.240']
            ip = '{}.{}.0.0/16'.format(ip_list[0], ip_list[1]) # 114.86.0.0/16

            # 数据库判断ip,已存在的无需加入防火墙
            res_retrieve = Ip.objects.filter(ip=ip)  # 查询
            if res_retrieve:    # 此ip数据库中已存在
                dic = {'status': 200, 'ip': '{} Already exists in the firewall'.format(ip)}
                return JsonResponse(dic)
            else:       # 此ip数据库中不存在    # 1.加入到数据库  2.加入到防火墙    3.防火墙持久化
                Ip(ip=ip).save()        # 插入
                # Ip.objects.filter(ip=ip).update(ip=ip)    # 更新
                # Ip.objects.filter(ip=ip).delete()         # 删除

                # rule_drop = {'protocol': 'tcp', 'target': 'DROP', 'tcp': {'dport': '8080'}}
                rule_accept = {'protocol': 'tcp', 'target': 'ACCEPT', 'src': ip}
                # iptc.easy.add_rule('filter', 'FORWARD', rule_drop,3)
                iptc.easy.add_rule('filter', 'FORWARD', rule_accept, 3)
                # iptc.easy.delete_rule('filter', 'FORWARD', rule_accept)

                # iptables --table filter --list FORWARD --line-numbers -n
                # iptables-save > /etc/sysconfig/iptables
                # iptables-restore < /etc/sysconfig/iptables
                # res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
                os.system('iptables-save > /etc/sysconfig/iptables')

                dic = {'status': 200, 'msg': '{} added firewall successfully'.format(ip)}
                return JsonResponse(dic)
        else:
            dic = {'status': 200, 'msg': 'failure! no ip'}
            return JsonResponse(dic)

    # def post(self, request):
    #     # http://192.168.1.240:8001/add_ip/
    #
    #     dic = {'status': 200, 'msg': 'sucess'}
    #     return JsonResponse(dic)


class delete_white_ip(APIView):

    def get(self, request):

        # http://192.168.1.240:8001/add_ip/?ip=114.87.177.174
        # print(request.query_params) # <QueryDict: {'ip': ['192.168.1.240'], 'name': ['abc']}>
        # print(type(request.query_params))   # <class 'django.http.request.QueryDict'>
        # print(request.query_params.get('ip',''))    # 192.168.1.240
        # print(type(request.query_params.get('ip','')))     # <class 'str'>
        ip = request.query_params.get('ip','')

        if ip:   # ip参数是否为空
            if ip == 'all':    # 删除数据库中所有的ip，删除防火墙规则
                Ip.objects.all().delete()
                os.system('firewall-cmd --reload')
                time.sleep(0.2)
                os.system('iptables -I FORWARD 3 -p tcp --dport 8080 -j DROP')
                os.system('iptables-save > /etc/sysconfig/iptables')
                dic = {'status': 200, 'ip': 'All ips removed'}
                return JsonResponse(dic)
            else:               # 删除数据库中单个ip，删除防火墙规则
                ip_list = ip.split('.', 2)  # ['192', '168', '1.240']
                ip = '{}.{}.0.0/16'.format(ip_list[0], ip_list[1]) # 114.86.0.0/16

                # 数据库判断ip,是否存在
                res_retrieve = Ip.objects.filter(ip=ip)  # 查询
                if res_retrieve:    # 此ip数据库中存在，删除数据库记录并删除防火墙
                    res_retrieve.delete()
                    rule_accept = {'protocol': 'tcp', 'target': 'ACCEPT', 'src': ip}
                    iptc.easy.delete_rule('filter', 'FORWARD', rule_accept)
                    os.system('iptables-save > /etc/sysconfig/iptables')
                    dic = {'status': 200, 'ip': '{} has been removed from the firewall'.format(ip)}
                    return JsonResponse(dic)
                else:       # 此ip数据库中不存在
                    dic = {'status': 200, 'msg': '{} does not exist in the database'.format(ip)}
                    return JsonResponse(dic)
        else:
            dic = {'status': 200, 'msg': 'failure! no ip'}
            return JsonResponse(dic)

    # def post(self, request):
    #     # http://192.168.1.240:8001/add_ip/
    #
    #     dic = {'status': 200, 'msg': 'sucess'}
    #     return JsonResponse(dic)


class check_white_ip(APIView):

    def get(self, request):

        # http://192.168.1.240:8001/add_ip/?ip=114.87.177.174
        # print(request.query_params) # <QueryDict: {'ip': ['192.168.1.240'], 'name': ['abc']}>
        # print(type(request.query_params))   # <class 'django.http.request.QueryDict'>
        # print(request.query_params.get('ip',''))    # 192.168.1.240
        # print(type(request.query_params.get('ip','')))     # <class 'str'>
        ip = request.query_params.get('ip','')

        if ip:   # ip参数是否为空
            if ip == 'all':    # 查询数据库中所有ip
                ip_list = []
                for ip in Ip.objects.all():
                    ip_list.append(ip.ip)
                dic = {'status': 200, 'ip': ip_list}
                return JsonResponse(dic)
            else:               # 查询某个ip是否存在
                ip_list = ip.split('.', 2)  # ['192', '168', '1.240']
                ip = '{}.{}.0.0/16'.format(ip_list[0], ip_list[1]) # 114.86.0.0/16

                # 数据库判断ip,是否存在
                res_retrieve = Ip.objects.filter(ip=ip)  # 查询
                if res_retrieve:    # 此ip数据库中存在
                    dic = {'status': 200, 'ip': '{} exists in the database'.format(ip)}
                    return JsonResponse(dic)
                else:       # 此ip数据库中不存在
                    dic = {'status': 200, 'msg': '{} does not exist in the database'.format(ip)}
                    return JsonResponse(dic)
        else:
            dic = {'status': 200, 'msg': 'failure! no ip'}
            return JsonResponse(dic)

    # def post(self, request):
    #     # http://192.168.1.240:8001/add_ip/
    #
    #     dic = {'status': 200, 'msg': 'sucess'}
    #     return JsonResponse(dic)
