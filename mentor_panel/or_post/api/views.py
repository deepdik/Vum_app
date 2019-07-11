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
from mentor_panel.or_post.models import *



import logging
logger = logging.getLogger('accounts')

class UploadPostView(APIView):
    permission_classes=[IsAuthenticated,]
    authentication_classes=[JSONWebTokenAuthentication,]
    def get(self,request,*args,**kwargs):
        logger.debug('Upload post get called')
        logger.debug(self.request.data)
        user=request.user
        ruser=RegisteredUser.objects.filter(user=user).first()
        data={}
        data['name']=ruser.name
        data['user_image']=''
        if ruser.profile_image:
            data['user_image']=ruser.profile_image

        return Response({
            'message':'data retrieved successfully',
            'success':'False',
            'data':data
        },status=HTTP_200_OK,)
    def post(self,request,*args,**kwargs):
        logger.debug('Upload post post called')
        logger.debug(self.request.data)
        serializer=UploadPostSerializer(data=request.data,context={'request':request})
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message':'Post created successfully',
                'success':'True',
                'data':serializer.data,
            },status=HTTP_200_OK)
        return Response({
            'message':'Post creation failed',
            'success':'False',
        },status=HTTP_400_BAD_REQUEST)

class MentorOwnPostListView(APIView):
    permission_classes=[IsAuthenticated,]
    authentication_classes=[JSONWebTokenAuthentication,]
    def get(self,request,*args,**kwargs):
        logger.debug('Mentor own post get called')
        logger.debug(self.request.data)
        user=request.user
        ruser=RegisteredUser.objects.filter(user=user).first()
        queryset=Post.objects.filter(user=ruser)
        serializer=SpecificMentorPostListSerializer(queryset,many=True,context={'request':request,})
        return Response({
            'message':'data retrieved successfully',
            'success':'True',
            'data':serializer.data,
        },status=HTTP_200_OK,)

class SpecificMentorPostListView(APIView):
    permission_classes=[IsAuthenticated,]
    authentication_classes=[JSONWebTokenAuthentication,]
    def get(self,request,*args,**kwargs):
        logger.debug('Specific Mentor post get called')
        logger.debug(self.request.data)
        id=self.kwargs['pk']
        ruser=RegisteredUser.objects.filter(id=id).first()
        queryset=Post.objects.filter(user=ruser)
        serializer=MentorPostListSerializer(queryset,many=True,context={'request':request,})
        return Response({
            'message':'data retrieved successfully',
            'success':'True',
            'data':serializer.data,
        },status=HTTP_200_OK,)

class FollowingMentorPostListView(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = [JSONWebTokenAuthentication]
    def get(self,request,*args,**kwargs):
        logger.debug('Following Mentor post list get called')
        logger.debug(self.request.data)

        user=request.user
        ruser=RegisteredUser.objects.filter(user=user).first()
        mentors=FollowingList.objects.filter(mentee=ruser).values('mentor')
        queryset=Post.objects.filter(user__in=mentors)

        serializer=MentorPostListSerializer(queryset,many=True,context={'request':request})
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':serializer.data,
        },status=HTTP_200_OK,)

class RemovePostView(APIView):
    permission_classes=[IsAuthenticated,]
    authentication_classes=[JSONWebTokenAuthentication,]
    def post(self,request,*args,**kwargs):
        logger.debug('Remove post post called')
        logger.debug(self.request.data)
        id=self.kwargs['pk']
        post=Post.objects.filter(id=id).first()
        if post:
            post.remove()
        else:
            return Response({
                'message':'This post does not exists.',
                'success':'False',
            },status=HTTP_400_BAD_REQUEST,)
        return Response({
            'message':'Post removed successfully',
            'success':'True',
        },status=HTTP_200_OK,)

class AddFavouritePostView(APIView):
    permission_classes=[IsAuthenticated,]
    authentication_classes=[JSONWebTokenAuthentication,]
    def post(self,request,*args,**kwargs):
        logger.debug('Add favpost post called')
        logger.debug(self.request.data)
        id=self.kwargs['pk']
        user=request.user
        post=Post.objects.filter(id=id).first()
        if post:
            ruser=RegisteredUser.objects.filter(user=user).first()
            if ruser:
                fp=FavPostList(
                    user=ruser,
                    post=post,
                )
                fp.save()
                return Response({
                    'message':'Post added as favourite',
                    'success':'True',
                },status=HTTP_200_OK,)
            return Response({
                'message':'You are not a registered user.',
                'success':'False',
            },status=HTTP_400_BAD_REQUEST,)
        return Response({
            'message':'Post does not exists',
            'success':'False',
        },status=HTTP_400_BAD_REQUEST,)

class CommentPostView(APIView):
    permission_classes=[IsAuthenticated,]
    authentication_classes=[JSONWebTokenAuthentication,]
    def post(self,request,*args,**kwargs):
        logger.debug('Comment post post called')
        logger.debug(self.request.data)
        id=self.kwargs['pk']
        user=request.user
        ruser=RegisteredUser.objects.filter(user=user).first()
        post=Post.objects.filter(id=id).first()
        data=request.data
        serializer=CommentPostSerializer(data=request.data,context={'ruser':ruser,'post':post})
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message':'Data saved successfully',
                'success':'True',
            },status=HTTP_200_OK,)
        return Response({
            'message':'Data can not be saved',
            'success':'False',
        },status=HTTP_400_BAD_REQUEST,)
