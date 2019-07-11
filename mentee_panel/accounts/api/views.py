from django.views.generic import TemplateView
from rest_framework.generics import (CreateAPIView,GenericAPIView,)
from rest_framework.views import (APIView)
# for geolocation
from geopy.geocoders import Nominatim
# from translate import Translator

from django.contrib.auth.models import User
from rest_framework.permissions import (AllowAny,IsAuthenticated,)
from django.utils.translation import ugettext_lazy as _
from rest_framework.response import Response
from rest_framework import status
from rest_framework.status import (
                                        HTTP_200_OK,
                                    	HTTP_400_BAD_REQUEST,
                                    	HTTP_204_NO_CONTENT,
                                    	HTTP_201_CREATED,
                                    	HTTP_500_INTERNAL_SERVER_ERROR,
                                )
from rest_framework_jwt.authentication import  JSONWebTokenAuthentication

from authy.api import AuthyApiClient
# authy_api = AuthyApiClient('9d7tyxSGhqgo91eRoCFPLOZYkVAKIdDt')
authy_api = AuthyApiClient('1RgplKT5SoUEl2cmR2tBqUk7KHckpbfG')
# authy_api = AuthyApiClient('u1ybgBGZQ07mnTwdI3IrLyu3Ay98AbbJ')


from .serializers import *
from mentee_panel.accounts.models import *


import logging
logger = logging.getLogger('accounts')


class RegisterView(CreateAPIView):
    serializer_class=RegisterSerializer
    permission_classes=[AllowAny,]
    def create(self,request,*args,**kwargs):
        logger.debug('register api called')
        logger.debug(request.data)
        serializer=self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)

        if serializer.data.get('user_type')=='1':
            country_code = serializer.data.get("country_code")
            phone_number = serializer.data.get("mobile")
            if phone_number and country_code:
                request = authy_api.phones.verification_start(phone_number, country_code,
                    via='sms', locale='en')

        return Response({
            'success':'True',
            'message': 'You have successfully registered, otp send',
            'data':serializer.data
        }, status=status.HTTP_201_CREATED, headers=headers)
class LoginView(APIView):
    permission_classes=[AllowAny]
    serializer_class = LoginSerializer
    def post(self,request,*args,**kwargs):
        logger.debug('User login post called')
        logger.debug(request.data)
        data=request.data
        serializer=LoginSerializer(data=data)
        if serializer.is_valid(raise_exception=True):
            new_data=serializer.data
            return Response({
                'success':'True',
                'message':'Successfully logged in',
                'data':new_data
            },status=HTTP_200_OK)
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

class ChangePasswordAfterSignInAPIView(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = [JSONWebTokenAuthentication]

    def get_object(self):
        logger.debug('Change password get called')
        logger.debug(self.request.data)
        return self.request.user

    def put(self,request,*args,**kwargs):
        logger.debug('Change password put called')
        logger.debug(request.data)
        user = self.get_object()
        serializer = ChangePasswordAfterSignInSerializer(data=request.data)
        if serializer.is_valid():
            oldPassword = serializer.data.get("oldPassword")
            newPassword = serializer.data.get("newPassword")
            confPassword = serializer.data.get("confPassword")
            if newPassword == confPassword:
                if not user.check_password(oldPassword):
                    return Response({
                            'success': 'False',
                            'message': "You entered wrong current password"},
                            status=HTTP_400_BAD_REQUEST
                        )

                user.set_password(newPassword)
                user.save()
                return Response({
                            'success':"True",
                            'message':'Your password change successfully',
                        },status=HTTP_200_OK)
            return Response({'success':"False","message":"New password and confirm password should be same"},
                            status=HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)
class ChangePasswordAfterVerificationAPIView(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = [JSONWebTokenAuthentication]

    def get_object(self):
        logger.debug('Change password get called')
        logger.debug(self.request.data)
        return self.request.user

    def put(self,request,*args,**kwargs):
        logger.debug('Change password put called')
        logger.debug(request.data)
        user = self.get_object()
        serializer = ChangePasswordAfterVerificationSerializer(data=request.data)
        if serializer.is_valid():
            newPassword = serializer.data.get("newPassword")
            confPassword = serializer.data.get("confPassword")
            if newPassword == confPassword:
                user.set_password(newPassword)
                user.save()
                return Response({
                            'success':"True",
                            'message':'Your password change successfully',
                        },status=HTTP_200_OK)
            return Response({'success':"False","message":"New password and confirm password should be same"},
                            status=HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=HTTP_400_BAD_REQUEST)

class OTPSendAPIView(APIView):
    '''
    Otp generate  for password reset apiview
    '''
    def post(self,request):
        logger.debug('otp send post called')
        logger.debug(request.data)
        phone_number = request.data['phonenumber']
        country_code = request.data['countrycode']
        if phone_number and country_code:
            user_qs = RegisteredUser.objects.filter(mobile=phone_number,country_code=country_code)
            if user_qs.exists():
                """
                for production version
                """
                request = authy_api.phones.verification_start(phone_number, country_code,
                    via='sms', locale='en')
                if request.content['success'] ==True:
                    return Response({
                        'success':"True",
                        'message':'OTP has been successfully sent to your registered mobile number'
                        },status=HTTP_200_OK)
                else:
                    return Response({
                        'success':"True",
                        'message':'Unable to send otp'
                        },status=HTTP_200_OK)
                """
                for development version
                """
            return Response({
                'success':"false",
                'message':"User with this number does not exist"
            },status=HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'success':"false",
                'message':"Provide details"
            },status=HTTP_400_BAD_REQUEST)
class OTPVerifyAPIView(APIView):
    # permission_classes = (IsAuthenticated,)
    # authentication_classes = [JSONWebTokenAuthentication]
    def post(self,request,*args,**kwargs):
        logger.debug('otp verify post called')
        logger.debug(request.data)
        data = request.data
        # user= request.user
        phone_number = data['phonenumber']
        country_code = data['countrycode']
        verification_code = data['verification_code']
        if phone_number and country_code and verification_code:
            check = authy_api.phones.verification_check(phone_number, country_code, verification_code)
            if check.ok()==True:
                obj = RegisteredUser.objects.filter(mobile=phone_number,country_code=country_code).first()
                obj.is_mobile_verified=True
                obj.save()
                return Response({
                    'success':"true",
                    'message':'Your number has been verified successfully'
                },status=HTTP_200_OK)

            return Response({
                'success':"false",
                'message':'verification code is incorrect'
            },status=HTTP_400_BAD_REQUEST)

        return Response({
            'success':"false",
            'message':'please provide data in valid format'
        },status=HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    permission_classes=[IsAuthenticated,]
    authentication_classes=[JSONWebTokenAuthentication,]
    def get(self,request,*args,**kwargs):
        logger.debug('User profile get called')
        logger.debug(request.data)
        queryset=RegisteredUser.objects.filter(user=request.user).first()
        serializer=UserProfileDetailSerializer(queryset)
        data=serializer.data
        data['email']=request.user.email
        return Response({
            'message':'data retrieved successfully',
            'success':'True',
            'data':data,
        },status=HTTP_200_OK,)

    def post(self,request, *args, **kwargs):
        logger.debug('User profile post called')
        logger.debug(request.data)
        data=request.data
        serializer = UserProfileUpdateSerializer(data=data, context={'request':request})
        if serializer.is_valid():

            country_code=data['country_code']
            mobile=data['mobile']
            email=data['email']
            imp1,imp2,imp3='0','0','0'

            user=request.user
            ruser=RegisteredUser.objects.filter(user=user).first()

            if country_code != ruser.country_code:
                imp1='1'
            if mobile != ruser.mobile:
                imp2='1'
            if email != user.email:
                imp3='1'

            serializer.save()
            data = serializer.data

            if ((imp1=='1' and imp2=='1') or imp1=='1' or imp2=='1') and imp3=='1':
                ruser.is_mobile_verified=False
                ruser.is_email_verified=False
                ruser.save()
                return Response({
                    'success':'True',
                    'message':'Data updated successfully. email and mobile needs varification.',
                    'data':data,
                },status=HTTP_200_OK)
            elif (imp1=='1' and imp2=='1') or imp1=='1' or imp2=='1':
                ruser.is_mobile_verified=False
                ruser.save()
                return Response({
                    'success':'True',
                    'message':'Data updated successfully. mobile needs varification.',
                    'data':data,
                },status=HTTP_200_OK)
            elif imp3=='1':
                ruser.is_email_verified=False
                return Response({
                    'success':'True',
                    'message':'Data updated successfully. email needs varification.',
                    'data':data,
                },status=HTTP_200_OK)
            else:
                return Response({
                    'success':'True',
                    'message':'Data updated successfully.',
                    'data':data,
                },status=HTTP_200_OK)

        return Response({
            'success':'False',
            'message':'Data update failed',
            'data':serializer.errors,
        },status=HTTP_400_BAD_REQUEST)
