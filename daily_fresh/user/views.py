from django.shortcuts import render, redirect

from django.http import HttpResponse, JsonResponse

import re, random

from django.contrib.auth import authenticate,login

from PIL import Image, ImageDraw, ImageFont

from django.views.generic import View

from django.core.mail import send_mail

from django.core.urlresolvers import reverse

from user.models import *

from celery_tasks.tasks import tasks_send_mail

from daily_fresh import settings

from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, SignatureExpired, BadSignature

from utils.user_util import LoginRequiredMixin

def index(request):
    return render(request, 'user/index.html')

class RegisterView(View):
    def get(self, request):
        return render(request, 'user/register.html')

    def post(self, request):
        user_name = request.POST.get('user_name')
        pwd = request.POST.get('pwd')
        cpwd = request.POST.get('cpwd')
        email = request.POST.get('email')
        allow = request.POST.get('allow')

        # # 判断用户是否填写了信息
        if not all([user_name, pwd, cpwd, email, allow]):
            return redirect('user:register_handle')

        # #判断姓名长度

        if len(user_name) < 5 or len(user_name) > 20:
            return render(request, 'user/register.html')

        # #验证用户名是否已经存在

        if User.objects.filter(username=user_name).count() != 0:
            return render(request, 'user/register.html')

        # #判断两次密码

        if pwd != cpwd or len(pwd) < 8 or len(pwd) > 20:
            return render(request, 'user/register.html')

        # # 验证邮箱

        if re.match("^[a-z0-9][\w\.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$", email) == None:  # re.match匹配失败时返回None

            return render(request, 'user/register.html')
        user = User.objects.create_user(user_name, email, pwd)
        user.is_active = 0
        user.save()

        # 加密用户的身份信息，生成激活token
        serializer = Serializer(settings.SECRET_KEY, 3600)
        info = {'confirm': user.id}
        token = serializer.dumps(info).decode()
        encryption_url = 'http://192.168.12.223:8000/user/active/%s' % token

        # 发邮件
        subject = '天天生鲜欢迎信息'  # 主题
        message = ''  # 文本内容
        sender = settings.EMAIL_FROM  # 发件人
        receiver = [email]  # 收件人，可以有多个
        html_message = '<h1>%s,欢迎您成为天天生鲜的注册会员</h1>请点击下面链接激活您的账户<br/><a href="%s">%s</a>' % (
        user_name, encryption_url, encryption_url)  # html内容
        tasks_send_mail.delay(subject, message, sender, receiver, html_message)  # 发送

        return render(request, 'user/index.html')


class ActiveView(View):
    def get(self, request, token):
        '''进行用户激活'''
        # 进行解密，获取要激活的用户信息
        serializer = Serializer(settings.SECRET_KEY, 3600)
        try:
            info = serializer.loads(token)
            # 获取待激活用户的id
            user_id = info['confirm']
            # 根据id获取用户信息
            user = User.objects.get(id=user_id)
            user.is_active = 1
            user.save()
            # 跳转到登录界面
            return redirect(reverse('user:login'))
        except SignatureExpired as e:
            return HttpResponse('激活链接已过期')
        except BadSignature as e:
            return HttpResponse('非法激活')


def user_exist(request):
    user_name = request.GET.get('user_name')
    count = User.objects.filter(username=user_name).count()
    return JsonResponse({'count': count})

class loginView(View):
    def get(self,request):
        remember_name = request.COOKIES.get('use_name', '')
        return render(request, 'user/login.html', {'remember_name': remember_name})
    def post(self,request):
        '''获取提交的信息'''
        user_name = request.POST.get('username')
        pwd = request.POST.get('pwd')
        verification = request.POST.get('verification', '')
        check = request.POST.get('checkbox')
        '''调用django的用户认证系统，进行用户认证'''
        user = authenticate(username=user_name, password=pwd)
        if user is not None:
            if user.is_active:
                if verification == '':
                    return render(request, 'user/login.html', {'verification_error': '验证码不能为空'})
                elif verification != request.session.get('verifycode').lower():
                    return render(request, 'user/login.html', {'verification_error': '验证码错误'})
                login(request, user)
                next_url=request.GET.get('next')
                if next_url:
                    resp = redirect(next_url)
                else:
                    resp = redirect(reverse('user:index'))
                if check == '1':
                    print('hahaha')
                    resp.set_cookie('use_name', user_name, 3600 * 24 * 7)
                else:
                    resp.set_cookie('use_name', user_name, 0)
                return resp
            else:
                return render(request, 'user/login.html', {'name_pwd_error': '该帐号尚未注册，请一小时内前往邮箱注册'})
        else:
            return render(request, 'user/login.html', {'name_pwd_error': '账号或密码错误'})


'''
LoginRequiredMixin的主要作用是封装视图as_view，
'''
class UserInfoView(LoginRequiredMixin,View):
    ''' 用户中心-信息页'''
    def get(self,request):
        context={'page':'1'}
        return render(request,'user/user_center_info.html',context)

class UserOrderView(LoginRequiredMixin,View):
    '''用户中心-订单页'''
    def get(self,request):
        context = {'page': '2'}
        return render(request,'user/user_center_order.html',context)

class UserAddressView(LoginRequiredMixin,View):
    '''用户中心-地址页'''
    def get(self,request):
        context = {'page': '3'}
        return render(request,'user/user_center_site.html',context)

















'''修改用户密码'''
class ForgetPasswordView(View):
    def get(self,request):
        return render(request, 'user/forget_password.html')
    def post(self,request):
        user_name=request.POST.get('user_name')
        email=request.POST.get('email')
        pwd=request.POST.get('pwd')
        cpwd=request.POST.get('cpwd')
        user=User.objects.filter(username=user_name)
        if user:
            if user[0].email!=email:
                context={'email_error': '该邮箱不是注册邮箱'}
                return render(request, 'user/forget_password.html',context)
            if len(pwd)<8 or len(pwd)>20:
                context={'pwd_error':'密码最短8位，最长20位'}
                return render(request, 'user/forget_password.html', context)
            if cpwd!=pwd:
                context={'cpwd_error':'两次输入的密码不一致'}
                return render(request, 'user/forget_password.html', context)
            else:
                # 加密用户的身份信息，生成激活token
                serializer = Serializer(settings.SECRET_KEY, 3600)
                info = {'confirm': user[0].id,'pwd':pwd}
                token = serializer.dumps(info).decode()
                encryption_url = 'http://192.168.12.223:8000/user/reset/%s' % token

                # 发邮件
                subject = '天天生鲜修改账户密码'  # 主题
                message = ''  # 文本内容
                sender = settings.EMAIL_FROM  # 发件人
                receiver = [email]  # 收件人，可以有多个
                html_message = '<h1>%s,欢迎您成为天天生鲜的注册会员</h1>请点击下面链接修改您的账户密码<br/><a href="%s">%s</a>' % (
                    user_name, encryption_url, encryption_url)  # html内容
                tasks_send_mail.delay(subject, message, sender, receiver, html_message)  # 发送

                return render(request, 'user/passwoed_success.html')
        else:
            return render(request,'user/forget_password.html',{'name_error':'该用户不存在'})
class ResetPwdView(View):
    def get(self, request, token):
        '''进行用户激活'''
        # 进行解密，获取要激活的用户信息
        serializer = Serializer(settings.SECRET_KEY, 3600)
        try:
            info = serializer.loads(token)
            # 获取待激活用户的id
            user_id = info['confirm']
            user_pwd = info['pwd']
            # 根据id获取用户信息
            user = User.objects.get(id=user_id)
            user.set_password(user_pwd)
            user.save()
            # 跳转到登录界面
            return redirect(reverse('user:login'))
        except SignatureExpired as e:
            return HttpResponse('激活链接已过期')
        except BadSignature as e:
            return HttpResponse('非法激活')
































def verification_code(request):
    bgcolor = (255, 255, 255)
    width = 100
    height = 25
    # 创建画面对象
    im = Image.new('RGB', (width, height), bgcolor)
    # 创建画笔对象
    draw = ImageDraw.Draw(im)
    # 调用画笔的point()函数绘制噪点
    for i in range(0, 100):
        xy = (random.randrange(0, width), random.randrange(0, height))
        fill = (random.randrange(0, 255), 255, random.randrange(0, 255))
        draw.point(xy, fill=fill)
    # 定义验证码的备选值
    str1 = 'ABCD123EFGHIJK456LMNOPQRS789TUVWXYZ0'
    # 随机选取4个值作为验证码
    rand_str = ''
    for i in range(0, 4):
        rand_str += str1[random.randrange(0, len(str1))]
    # 构造字体对象
    font = ImageFont.truetype('/usr/share/fonts/truetype/freefont/FreeMonoBold.ttf', 23)
    # 构造字体颜色
    fontcolor = (255, random.randrange(0, 255), random.randrange(0, 255))
    # 绘制4个字
    for i in range(0, 4):
        draw.text((5 + 24 * i, 2), rand_str[i], font=font, fill=fontcolor)
    # 释放画笔
    del draw
    # 存入session，用于做进一步验证
    request.session['verifycode'] = rand_str
    # 内存文件操作
    from io import BytesIO
    buf = BytesIO()
    # 将图片保存在内存中，文件类型为png
    im.save(buf, 'png')
    # 将内存中的图片数据返回给客户端，MIME类型为图片png
    return HttpResponse(buf.getvalue(), 'image/png')
