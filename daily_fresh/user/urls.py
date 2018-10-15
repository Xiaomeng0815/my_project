"""daily_fresh URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.8/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""
from django.conf.urls import include, url
from user import views
from django.contrib.auth.decorators import login_required

urlpatterns = [
    url(r'^index$',views.index,name='index'),
    url(r'^register$',views.RegisterView.as_view(),name='register'),#注册及注册处理
    url(r'^active/(?P<token>.*)$',views.ActiveView.as_view(),name='active'),#激活账号
    url(r'^login$',views.loginView.as_view(),name='login'),#登录及登录处理
    url(r'^center_info$',views.UserInfoView.as_view(),name='UserInfo'), #用户中心-信息页
    url(r'^center_order$',views.UserOrderView.as_view(),name='UserOrder'),#用户中心-订单页
    url(r'^center_address$',views.UserAddressView.as_view(),name='UserAddress'),#用户中心-地址页




    url(r'^forget_password$',views.ForgetPasswordView.as_view(),name='forget_password'),
    url(r'^reset/(?P<token>.*)$',views.ResetPwdView.as_view(),name='reset'),

    url(r'^user_exist$',views.user_exist,name='user_exist'),
    url(r'^verification_code$',views.verification_code,name='verification_code'),
]
