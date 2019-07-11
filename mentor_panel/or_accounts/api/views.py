from django.views.generic import TemplateView
from rest_framework.generics import (CreateAPIView,GenericAPIView,ListAPIView,RetrieveAPIView)
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
from mentor_panel.or_accounts.models import *
# from .permissions import *


import logging
logger = logging.getLogger('accounts')

class CategoryListView(ListAPIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)
    queryset=Category.objects.all()
    def list(self,request,*args,**kwargs):
        serializer=CategoryListSerializer(self.get_queryset(),many=True,context={'request':request})
        data=serializer.data
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':data,
        },status=HTTP_200_OK,)

class CourseByCategoryListView(ListAPIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)

    def list(self,request,*args,**kwargs):
        id=self.kwargs['pk']
        cat=Category.objects.filter(id=id).first()
        queryset=Course.objects.filter(course_category=cat)
        serializer=CourseByFilterListSerializer(queryset,many=True,context={'request':request})
        data=serializer.data
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':data,
        },status=HTTP_200_OK,)

class PopularCourseByCategoryListView(ListAPIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)

    def list(self,request,*args,**kwargs):
        id=self.kwargs['pk']
        cat=Category.objects.filter(id=id).first()
        queryset=Course.objects.filter(course_category=cat,rating__gte=3)
        serializer=CourseByFilterListSerializer(queryset,many=True,context={'request':request})
        data=serializer.data
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':data,
        },status=HTTP_200_OK,)

class MentorByCategoryListView(ListAPIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)

    def list(self,request,*args,**kwargs):
        id=self.kwargs['pk']
        cat=Category.objects.filter(id=id).first()
        queryset=RegisteredUser.objects.filter(category=cat,user_type='2')
        serializer=MentorByFilterListSerializer(queryset,many=True,context={'request':request})
        data=serializer.data
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':data,
        },status=HTTP_200_OK,)

class PopularMentorByCategoryListView(ListAPIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)

    def list(self,request,*args,**kwargs):
        id=self.kwargs['pk']
        cat=Category.objects.filter(id=id).first()
        queryset=RegisteredUser.objects.filter(category=cat,rating__gte=3,user_type='2')
        serializer=MentorByFilterListSerializer(queryset,many=True,context={'request':request})
        data=serializer.data
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':data,
        },status=HTTP_200_OK,)

class MentorDetailView(RetrieveAPIView):
    def get(self,request,*args,**kwargs):
        id=self.kwargs['pk']
        queryset=RegisteredUser.objects.filter(id=id).first()
        if queryset:
            cat=queryset.category
            context={'cat':cat}
            serializer=MentorDetailSerializer(queryset,context={'request':request,'cat':cat})
            return Response({
                'message':'Data retrieved successfully',
                'success':'True',
                'data':serializer.data
            },status=HTTP_200_OK,)

class AddCourseView(APIView):
    # IsMentor,
    permission_classes=[IsAuthenticated,]
    serializer_class = LoginSerializer
    def post(self,request,*args,**kwargs):
        logger.debug('create course post called')
        logger.debug(request.data)
        user=request.user
        data=request.data
        print('hello')
        serializer=AddCourseSerializer(data=data,context={'user':user,'request':request})
        print('hi')
        if serializer.is_valid():
            serializer.save()
            data=serializer.data

            return Response({
                'message':'Course created successfully. Waiting admin approval.',
                'success':'True',
                'data':data,
            },status=HTTP_200_OK,)
        return Response({
            'message':serializer.errors,
            'success':'False',
        },status=HTTP_400_BAD_REQUEST,)

class AddVideoView(APIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)
    def post(self,request,*args,**kwargs):
        logger.debug('Inside Add Video post')
        logger.debug(request.data)
        print('inside add video post')
        pk=self.kwargs['pk']
        c=Course.objects.filter(id=pk).first()
        print('1')
        if c:
            print('2')
            serializer=AddVideoSerializer(data=request.data,context={'request':request,'course':c})
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'message':'Video added to the course successfully',
                    'success':'True',
                    'data':serializer.data,
                },status=HTTP_200_OK,)
            return Response({
                'message':'Video upload failed',
                'success':'False',
            },status=HTTP_400_BAD_REQUEST,)
        else:
            return Response({
                'message':'No course available with this id',
                'success':'False',
            },status=HTTP_400_BAD_REQUEST,)

class CourseListView(ListAPIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)
    serializer_class=CourseListSerializer
    queryset=Course.objects.filter(active=True,approved=True)
    def list(self,request,*args,**kwargs):
        logger.debug('Inside Course List View list')
        serializer=CourseListSerializer(self.get_queryset(),many=True,context={'request':request})
        data=serializer.data
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':data,
        },status=HTTP_200_OK,)

class CourseDetailView(RetrieveAPIView):
    def get(self,request,*args,**kwargs):
        id=self.kwargs['pk']
        queryset=Course.objects.filter(id=id).first()
        if queryset:
            cat=queryset.course_category
            context={'cat':cat}
            serializer=CourseDetailSerializer(queryset,context={'request':request,'cat':cat})
            return Response({
                'message':'Data retrieved successfully',
                'success':'True',
                'data':serializer.data
            },status=HTTP_200_OK,)

class AddToWishListView(APIView):
    def get(self,request,*args,**kwargs):
        id=self.kwargs['pk']
        course=Course.objects.filter(id=id).first()
        user=request.user
        ruser=RegisteredUser.objects.filter(user=user).first()
        wlobj=WishList.objects.filter(course=course,user=ruser).first()
        if wlobj:
            return Response({
                'message':'Already inside wishlist',
                'success':'False',
            },status=HTTP_400_BAD_REQUEST,)
        wl=WishList(
            user=ruser,
            course=course,
        )
        wl.save()
        return Response({
            'message':'Data updated successfully',
            'success':'True',
        },status=HTTP_200_OK,)

class CourseByMentorListView(ListAPIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)

    def list(self,request,*args,**kwargs):
        id=self.kwargs['pk']
        ruser=RegisteredUser.objects.filter(id=id).first()
        queryset=Course.objects.filter(course_mentor=ruser)
        serializer=CourseByFilterListSerializer(queryset,many=True,context={'request':request})
        data=serializer.data
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':data,
        },status=HTTP_200_OK,)

class FollowersByMentorListView(ListAPIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)

    def list(self,request,*args,**kwargs):
        id=self.kwargs['pk']
        ruser=RegisteredUser.objects.filter(id=id).first()
        mentees=FollowingList.objects.filter(mentor=ruser)
        queryset=RegisteredUser.objects.filter(id__in=mentees)
        serializer=MentorByFilterListSerializer(queryset,many=True,context={'request':request})
        data=serializer.data
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':data,
        },status=HTTP_200_OK,)

class FollowersOfMentorListView(ListAPIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)

    def list(self,request,*args,**kwargs):
        user=request.user
        ruser=RegisteredUser.objects.filter(user=user).first()
        mentees=FollowingList.objects.filter(mentor=ruser)
        queryset=RegisteredUser.objects.filter(id__in=mentees)
        serializer=MentorByFilterListSerializer(queryset,many=True,context={'request':request})
        data=serializer.data
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':data,
        },status=HTTP_200_OK,)

class WishListByUserListView(ListAPIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)
    serializer_class=WishListByUserListSerializer

    def list(self,request):
        logger.debug('Inside wishlist View list')
        user=request.user
        ruser=RegisteredUser.objects.filter(user=user).first()
        queryset=WishList.objects.filter(user=ruser)
        serializer=WishListByUserListSerializer(queryset,many=True,context={'request':request})
        data=serializer.data
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':data,
        },status=HTTP_200_OK,)
