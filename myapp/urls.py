
from django.urls import path
from . import views
urlpatterns = [
    # user API's
    path('signup/', views.RegisterUserView.as_view()),
    path('verify-otp/', views.VerifyOTPAndRegisterView.as_view()),
    path('login/' , views.Loginuser.as_view()),
    path('users/', views.get_all_users),

    # admin API's
    path('hidden_gems/', views.HiddenGemList.as_view()),
    path('hidden_gems/<str:pk>/', views.HiddenGemDetail.as_view()),

    # Guide API's
    path('guides/', views.GuideListCreateAPIView.as_view()),
    path('guides/<str:pk>/', views.GuideDetailAPIView.as_view()),

    # custompackage API's
    path('custom-package/',views.CreateCustomPackage.as_view()),
    # Booking API's
    path('booking-history/',views.BookingHistoryView.as_view()),
    path('bookhiddengem/',views.BookHiddenGem.as_view()),
    path('bookcustompackage/' , views.BookCustomPackage.as_view()),
]