from rest_framework import serializers
from rest_framework_jwt.settings import api_settings
from rest_framework.exceptions import APIException
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm

from django.utils.translation import ugettext_lazy as _
from django.conf import settings

from mentee_panel.accounts.models import *
from mentor_panel.or_accounts.models import *

from mentor_panel.or_accounts.api.serializers import *
from mentor_panel.or_post.api.serializers import *
from mentee_panel.enrollment.models import *



import logging
logger = logging.getLogger('accounts')

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

# open_course_url=serializers.HyperlinkedIdentityField()
# remove_course_url=serializers.HyperlinkedIdentityField()
# rate_course_url=serializers.HyperlinkedIdentityField()
write_a_review_url=serializers.HyperlinkedIdentityField(view_name='mentee_review:mr_video',lookup_field='pk')
# get_certificate_url=serializers.HyperlinkedIdentityField()

class APIException400(APIException):
    status_code = 400

class MenteeHomeScreenSerializer(serializers.ModelSerializer):
    trending_mentors=serializers.SerializerMethodField()
    popular_courses=serializers.SerializerMethodField()
    following_mentor_posts=serializers.SerializerMethodField()
    class Meta:
        model=RegisteredUser
        fields=('trending_mentors','popular_courses','following_mentor_posts')

    def get_trending_mentors(self,instance):
        request=self.context['request']
        queryset=RegisteredUser.objects.filter(user_type='2')#,rating__gte=3
        print(queryset)
        serializer=MentorByFilterListSerializer(queryset,many=True,context={'request':request})
        return serializer.data
    #
    def get_popular_courses(self,instance):
        request=self.context['request']
        queryset=Course.objects.filter(rating__gte=3)
        serializer=CourseByFilterListSerializer(queryset,many=True,context={'request':request})
        return serializer.data
    #
    def get_following_mentor_posts(self,instance):
        request=self.context['request']
        user=request.user
        ruser=RegisteredUser.objects.filter(user=user).first()
        mentors=FollowingList.objects.filter(mentee=ruser).values('mentor')
        queryset=Post.objects.filter(user__in=mentors)

        serializer=MentorPostListSerializer(queryset,many=True,context={'request':request})
        print('hi')
        return serializer.data

class EnrolledCourseListSerializer(serializers.ModelSerializer):
    status=serializers.SerializerMethodField()
    duration_left=serializers.SerializerMethodField()
    number_of_videos=serializers.SerializerMethodField()
    # open_course_url=open_course_url
    # remove_course_url=remove_course_url
    # rate_course_url=rate_course_url
    class Meta:
        model=Course
        fields=('id','course_name','course_cover_image','status','duration_left',)
        # 'open_course_url','remove_course_url','rate_course_url')
        #,'duration','number_of_videos')#'open_course_url'
    def get_status(self,instance):
        ruser=self.context['mentee']
        mcr=MenteeCourseRegistration.objects.filter(course=instance,mentee=ruser).first()
        return mcr.status
    def get_duration_left(self,instance):
        ruser=self.context['mentee']
        mcr=MenteeCourseRegistration.objects.filter(course=instance,mentee=ruser)
        duration_left=mcr.duration_left
        hr=int(duration_left/(60*60))
        duration_left=duration_left-(hr*60*60)
        min=int(duration_left/60)
        # total_duration=total_duration-(min*60)
        # sec=int(total_duration)
        # l=print(len(str(hr)))
        # hr = '00' if hr==0 else hr
        return str(hr)+':'+str(min)+' min left'
        # return str(hr)+':'+str(min)+':'+str(sec)+' min'
    def get_number_of_videos(self,instance):
        return instance.total_number_of_videos

class OpenCourseSerializer(serializers.ModelSerializer):
    video_detail=serializers.SerializerMethodField()
    write_a_review_url=write_a_review_url
    class Meta:
        model=Course
        fields=('video_detail','course_name','course_desc','write_a_review_url')
    def get_video_detail(self,instance):
        ruser=self.context['ruser']
        mcr=MenteeCourseRegistration.objects.filter(course=instance,mentee=ruser).first()
        lv=mcr.last_video_watched
        '''
        id*
        video_watch_duration*
        video_total_duration*
        video_status*
        video_title*
        video_url*
        video_cover_image*
        get_certificate_url
        next_video_url
        prev_video_url
        '''

        lv_vwl=VideoWatchList.objects.filter(video=lv,mentee=ruser).first()
        if lv_vwl.video_watch_duration >= lv_vwl.video_total_duration:
            cvn=CourseVideo.objects.filter(video_serial_no=(lv.video_serial_no+1),course=mcr.course).first()
            if cvn:
                mcr.last_video_watched=cvn
                mcr.save()
                lv=mcr.last_video_watched
                lv_vwl=VideoWatchList.objects.filter(video=lv,mentee=ruser).first()

        cvn=CourseVideo.objects.filter(video_serial_no=(lv.video_serial_no+1),course=mcr.course).first()
        cvp=CourseVideo.objects.filter(video_serial_no=(lv.video_serial_no-1),course=mcr.course).first()
        if lv_vwl.video_watch_duration <= lv_vwl.video_total_duration:
            data['video_id']=lv.id
            data['video_title']=lv.video_title
            data['video_cover_image']=lv.video_cover_image
            data['video_url']=lv.video
            data['video_total_duration']=lv_vwl.video_total_duration
            data['video_watch_duration']=lv_vwl.video_watch_duration
            data['video_status']=lv_vwl.video_status
            data['next_video_url']=""
            data['prev_video_url']=""
            data['get_certificate_url']=""
            if cvn:
                data['next_video_url']=cvn.video
            else:
                if mcr.status == 'Completed':
                    data['get_certificate_url']=get_certificate_url
            if cvp:
                data['prev_video_url']=cvp.video

        return data
