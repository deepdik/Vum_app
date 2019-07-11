from django.views.generic import TemplateView
from rest_framework.generics import (CreateAPIView,GenericAPIView,ListAPIView)
from rest_framework.views import (APIView)
from rest_framework.filters import (SearchFilter,OrderingFilter,)
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
from mentor_panel.or_accounts.models import *
from mentor_panel.or_accounts.api.serializers import *
from mentor_panel.or_post.api.serializers import *
from mentee_panel.enrollment.models import *


import logging
logger = logging.getLogger('accounts')


class MenteeHomeScreenView(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = [JSONWebTokenAuthentication]
    def get(self,request,*args,**kwargs):
        logger.debug('Mentee home get called')
        logger.debug(self.request.data)
        queryset=RegisteredUser.objects.filter(id=1)
        serializer=MenteeHomeScreenSerializer(queryset,many=True,context={'request':request})
        data=serializer.data
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':data,
        },status=HTTP_200_OK,)

        # queryset1=RegisteredUser.objects.filter(user_type='2')#,rating__gte=3
        # serializer1=MentorByFilterListSerializer(queryset1,many=True,context={'request':request})
        # data=serializer1.data.copy()
        #
        # queryset2=Course.objects.filter()#rating__gte=3
        # serializer2=CourseByFilterListSerializer(queryset2,many=True,context={'request':request})
        # data.append(serializer2.data)
        #
        # user=request.user
        # ruser=RegisteredUser.objects.filter(user=user).first()
        # mentors=FollowingList.objects.filter(mentee=ruser).values('mentor')
        # queryset3=Post.objects.filter(user__in=mentors)
        # serializer3=MentorPostListSerializer(queryset3,many=True)
        # data.append(serializer3.data)
        # print('hello')

class MenteeHomeScreenSearchView(ListAPIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)
    serializer_class=CategoryListSerializer
    filter_backends=(SearchFilter,OrderingFilter,)
    search_fields=['slug','name']

    def get_queryset(self,*args,**kwargs):
        query=self.request.GET.get('q',None)
        query=query.lower()
        if query:
            queryset=Category.objects.filter(
                Q(name__icontains=query)|
                Q(slug__icontains=query)
            ).distinct()
        return queryset

    def list(self,request,*args,**kwargs):
        logger.debug('Mentor home search post called')
        logger.debug(self.request.data)
        queryset=self.get_queryset()
        serializer=CategoryListSerializer(queryset,many=True,context={'request':request})
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':serializer.data,
        },status=HTTP_200_OK,)

class FollowingMentorListView(APIView):
    def get(self,request,*args,**kwargs):
        user=request.user
        ruser=RegisteredUser.objects.filter(user=user).first()
        mentors=FollowingList.objects.filter(mentee=ruser).values('mentor')
        queryset=RegisteredUser.objects.filter(id__in=mentors)
        serializer=MentorByFilterListSerializer(queryset,many=True,context={'request':request})
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':serializer.data,
        },status=HTTP_200_OK,)

class EnrolledCourseListView(APIView):
    def get(self,request,*args,**kwargs):
        user=request.user
        ruser=RegisteredUser.objects.filter(user=user).first()
        courses=MenteeCourseRegistration.objects.filter(mentee=ruser).values('course')
        queryset=Course.objects.filter(id__in=courses)
        serializer=EnrolledCourseListSerializer(queryset,many=True,context={'request':request,'mentee':ruser})
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':serializer.data,
        },status=HTTP_200_OK,)

class UpdateVideoDurationView(APIView):
    def post(self,request,*args,**kwargs):
        id=self.kwargs['pk']
        user=request.user
        video_id=request.data['v_id']
        duration_played=request.data['duration_played']

        ruser=RegisteredUser.objects.filter(user=user).first()
        course=Course.objects.filter(id=id).first()
        cv=CourseVideo.objects.filter(id=video_id).first()

        vwl=VideoWatchList.objects.filter(mentee=ruser,course=course,video=cv).first()

        vwl.video_watch_duration = duration_played
        if duration_played >= vwl.video_total_duration:
            if video_status != 'Completed':
                vwl.video_status='Completed'
        else:
            vwl.video_status='In Progress'
        vwl.save()
        mcr=MenteeCourseRegistration.objects.filter(mentee=ruser,course=course).first()
        mcr.last_video_watched=cv
        vwl_compl_count=VideoWatchList.objects.filter(mentee=ruser,course=course,video_status="Completed").count()
        if vwl_compl_count == course.total_number_of_videos:
            if mcr.status != 'Completed':
                mcr.status='Completed'
        else:
            mcr.status='In Progress'
        mcr.save()
        return Response({
            'message':'Data saved successfully',
            'success':'True',
        },status=HTTP_200_OK,)


class OpenCourseView(APIView):
    def get(self,request,*args,**kwargs):
        user=request.user
        ruser=RegisteredUser.objects.filter(user=user).first()
        id=self.kwargs['pk']
        queryset=Course.objects.filter(id=id)
        serializer=OpenCourseSerializer(queryset,context={'request':request,'ruser':ruser})
        return Response({
            'message':'data retrieved successfully',
            'success':'True',
            'data':serializer.data,
        },status=HTTP_200_OK,)
