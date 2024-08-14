
from django.urls import path

from . import views
urlpatterns = [
    path('home/', views.home),
    path('signup/', views.RegisterUserView.as_view()),
    path('verify-otp/', views.VerifyOTPAndRegisterView.as_view()),
    path('login/' , views.Loginuser.as_view()),
    path('users/', views.get_all_users),

]
