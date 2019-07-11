from django.urls import path

from .views import *

app_name='mentee_accounts'

urlpatterns=[
    path('register/',RegisterView.as_view(),name='ee_acc_register'),
    path('login/',LoginView.as_view(),name='ee_acc_login'),
    path('otp/send/', OTPSendAPIView.as_view(),name="ee_acc_otpsend"),
    path('otp/verify/', OTPVerifyAPIView.as_view(),name="ee_acc_otpverify"),
    path('forgotpass/changepassword/',ChangePasswordAfterSignInAPIView.as_view(),name='ee_acc_change_pass_after_verification'),
    path('profile/changepassword/',ChangePasswordAfterSignInAPIView.as_view(),name='ee_acc_change_pass_by_profile'),
    path('profile/',UserProfileView.as_view(),name='ee_acc_profile'),
    path('profile/update/',UserProfileView.as_view(),name='ee_acc_profile_edit'),
]
