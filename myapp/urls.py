from django.urls import path
from . import views
urlpatterns = [
    # user API's
    path('home/', views.home),
    path('signup/', views.RegisterUserView.as_view()),
    path('verify-otp/', views.VerifyOTPAndRegisterView.as_view()),
    path('login/' , views.Loginuser.as_view()),
    path('users/', views.get_all_users),

    # API's for admin
    path('hidden_gems/', views.HiddenGemList.as_view()),
    path('hidden_gems/<str:pk>/', views.HiddenGemDetail.as_view()),

#     Guide API's
    path('guides/', views.GuideListCreateAPIView.as_view()),
    path('guides/<str:pk>/', views.GuideDetailAPIView.as_view()),

]
