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
from mentee_panel.enrollment.models import *
from mentee_panel.accounts.api.serializers import LoginSerializer
from mentee_panel.accounts.models import *
from mentor_panel.or_accounts.models import Course

import logging
logger = logging.getLogger('accounts')

class EnrollCourseView(APIView):
    def post(self,request,*args,**kwargs):
        id=self.kwargs['pk']
        user=request.user
        course=Course.objects.filter(id=id).first()
        total_duration=course.total_duration
        ruser=RegisteredUser.objects.filter(user=user).first()
        course_first_video=CourseVideo.objects.filter(course=course).order_by('video_serial_no').first()
        mcr=MenteeCourseRegistration(
            mentee=ruser,
            course=course,
            total_duration=total_duration,
            duration_left=total_duration,
            last_video_watched=course_first_video,
        )
        mcr.save()
        cvlist=CourseVideo.objects.filter(course=course)
        for cv in cvlist:
            vwl=VideoWatchList(
                mentee=ruser,
                course=course,
                video=cv,
                video_serial_no=cv.video_serial_no,
                video_watch_duration=0,
                video_total_duration=cv.video_length_in_seconds
            )
            vwl.save()

        return Response({
            'message':'Course enrolled Successfully',
            'success':'Ture',
        },status=HTTP_200_OK,)
