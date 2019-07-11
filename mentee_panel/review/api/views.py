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

from .serializers import *
from mentee_panel.accounts.api.serializers import LoginSerializer
from mentee_panel.accounts.models import *
from mentor_panel.or_accounts.models import Course,CourseVideo

import logging
logger = logging.getLogger('accounts')

class CourseReviewView(APIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)
    def post(self,request,*args,**kwargs):
        logger.debug('Inside Course Review post')
        logger.debug(request.data)
        id=self.kwargs['pk']
        cr=Course.objects.filter(id=id).first()
        if cr:
            ru=RegisteredUser.objects.filter(user=request.user).first()
            if ru and ru.user_type=='1':
                serializer=CourseReviewSerializer(data=request.data,context={'ruser':ru,'course':cr})
                if serializer.is_valid():
                    serializer.save()
                    data=serializer.data
                    return Response({
                        'message':'Data submitted successfully',
                        'success':'True',
                        'data':data,
                    },status=HTTP_200_OK)
                return Response({
                    'message':'Data submition failed',
                    'success':'False',
                },status=HTTP_400_BAD_REQUEST)
            else:
                return Response({
                    'message':'You must be a mentee to review a course',
                    'success':'False',
                },status=HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'message':'No course available with that id',
                'success':'False',
            },status=HTTP_400_BAD_REQUEST)

class MentorReviewView(APIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)
    def post(self,request,*args,**kwargs):
        logger.debug('Inside Mentor Review post')
        logger.debug(request.data)
        id=self.kwargs['pk']
        mentor=RegisteredUser.objects.filter(id=id).first()
        if mentor and mentor.user_type=='2':
            ruser=RegisteredUser.objects.filter(user=request.user).first()
            if ruser and ruser.user_type=='1':
                serializer=MentorReviewSerializer(data=request.data,context={'ruser':ruser,'mentor':mentor})
                if serializer.is_valid():
                    serializer.save()
                    data=serializer.data
                    return Response({
                        'message':'Data submitted successfully',
                        'success':'True',
                        'data':data,
                    },status=HTTP_200_OK)
                return Response({
                    'message':'Data submition failed',
                    'success':'False',
                },status=HTTP_400_BAD_REQUEST)
            else:
                return Response({
                    'message':'You must be a mentee to review a mentor.',
                    'success':'False',
                },status=HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'message':'The user id that you have provided is not a mentor',
                'success':'False',
            },status=HTTP_400_BAD_REQUEST)

class VideoReviewView(APIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)
    def post(self,request,*args,**kwargs):
        logger.debug('Inside Video Review post')
        logger.debug(request.data)
        id=self.kwargs['pk']
        video=CourseVideo.objects.filter(id=id).first()
        if video:
            ruser=RegisteredUser.objects.filter(user=request.user).first()
            if ruser and ruser.user_type=='1':
                serializer=VideoReviewSerializer(data=request.data,context={'ruser':ruser,'video':video})
                if serializer.is_valid():
                    serializer.save()
                    data=serializer.data
                    return Response({
                        'message':'Data submitted successfully',
                        'success':'True',
                        'data':data,
                    },status=HTTP_200_OK)
                return Response({
                    'message':'Data submition failed',
                    'success':'False',
                    'data':serializer.errors,
                },status=HTTP_400_BAD_REQUEST)
            else:
                return Response({
                    'message':'You must be a mentee to review a video.',
                    'success':'False',
                },status=HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'message':'No video available with this id',
                'success':'False',
            },status=HTTP_400_BAD_REQUEST)

class ReviewListByCourseView(APIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)
    def get(self,request,*args,**kwargs):
        logger.debug('Inside Review list by course get')
        logger.debug(request.data)
        id=self.kwargs['pk']
        course=Course.objects.filter(id=id).first()
        queryset=CourseReview.objects.filter(course=course)
        serializer=ReviewListByCourseSerializer(queryset,many=True)
        return Response({
            'message':'data retrieved successfully',
            'success':'True',
            'data':serializer.data
        },status=HTTP_200_OK,)

class ReviewListByMentorView(APIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)
    def get(self,request,*args,**kwargs):
        logger.debug('Inside Review list by mentor get')
        logger.debug(request.data)
        id=self.kwargs['pk']
        mentor=RegisteredUser.objects.filter(id=id).first()
        queryset=MentorReview.objects.filter(mentor=mentor)
        serializer=ReviewListByMentorSerializer(queryset,many=True)
        return Response({
            'message':'data retrieved successfully',
            'success':'True',
            'data':serializer.data
        },status=HTTP_200_OK,)


class ReviewListByVideoView(APIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)
    def get(self,request,*args,**kwargs):
        logger.debug('Inside Review list by video get')
        logger.debug(request.data)
        id=self.kwargs['pk']
        video=CourseVideo.objects.filter(id=id).first()
        queryset=VideoReview.objects.filter(video=video)
        serializer=ReviewListByVideoSerializer(queryset,many=True)
        return Response({
            'message':'data retrieved successfully',
            'success':'True',
            'data':serializer.data
        },status=HTTP_200_OK,)
