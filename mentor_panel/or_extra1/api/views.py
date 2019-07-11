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
from mentor_panel.or_accounts.api.serializers import *
from mentor_panel.or_post.api.serializers import *


import logging
logger = logging.getLogger('accounts')

class MentorHomeScreenView(APIView):
    permission_classes = (IsAuthenticated,)
    authentication_classes = [JSONWebTokenAuthentication]
    def get(self,request,*args,**kwargs):
        logger.debug('Mentor home get called')
        logger.debug(self.request.data)

        user=request.user
        ruser=RegisteredUser.objects.filter(user=user).first()
        queryset=Post.objects.filter(user=ruser)
        serializer=SpecificMentorPostListSerializer(queryset,many=True,context={'request':request})
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':serializer.data,
        },status=HTTP_200_OK,)

class MentorHomeScreenSearchView(ListAPIView):
    permission_classes=(IsAuthenticated,)
    authentication_classes=(JSONWebTokenAuthentication,)
    serializer_class=MentorByFilterListSerializer
    filter_backends=(SearchFilter,OrderingFilter,)
    search_fields=['slug','name']

    def get_queryset(self,*args,**kwargs):
        query=self.request.GET.get('q',None)
        query=query.lower()
        if query:
            queryset=RegisteredUser.objects.filter(
                (Q(name__icontains=query)|
                Q(slug__icontains=query))&
                Q(user_type='2')
            ).distinct()
        return queryset

    def list(self,request,*args,**kwargs):
        logger.debug('Mentor home search post called')
        logger.debug(self.request.data)
        queryset=self.get_queryset()
        serializer=MentorByFilterListSerializer(queryset,many=True,context={'request':request})
        return Response({
            'message':'Data retrieved successfully',
            'success':'True',
            'data':serializer.data,
        },status=HTTP_200_OK,)
