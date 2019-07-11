from rest_framework import serializers
from rest_framework_jwt.settings import api_settings
from rest_framework.exceptions import APIException
from django.db.models import Sum

from mentee_panel.accounts.models import *
from mentor_panel.or_accounts.models import *
from mentor_panel.or_post.models import *
from mentee_panel.review.models import *
#
import logging
logger = logging.getLogger('accounts')
#
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
#
class APIException400(APIException):
    status_code = 400

class CourseReviewSerializer(serializers.ModelSerializer):
    points=serializers.CharField(max_length=5,allow_blank=True)
    desc=serializers.CharField(max_length=200,allow_blank=True)
    class Meta:
        model=CourseReview
        fields=('points','desc')
#
    def validate(self,data):
        points=data['points']
        desc=data['desc']
        course=self.context['course']
        ruser=self.context['ruser']


        if not points or points=="":
            raise APIException400({
                'message':'Please provide raing',
                'success':'False',
            })
        if not desc or desc=="":
            raise APIException400({
                'message':'Please write something as review',
                'success':'False',
            })
        if points not in ('1','2','3','4','5'):
            raise APIException400({
                'message':'Please provide rating between 1 to 5',
                'success':'False',
            })

        cr_q=CourseReview.objects.filter(course=course,user=ruser).first()

        if cr_q:
            raise APIException400({
                'message':'You have already given your review for this course.',
                'success':'False',
            })

        return data

    def create(self,validated_data):
        ruser=self.context['ruser']
        course=self.context['course']
        points=validated_data['points']
        desc=validated_data['desc']
        cr=CourseReview(
            course=course,
            user=ruser,
            points=points,
            desc=desc,
        )
        cr.save()

        a=CourseReview.objects.filter(course=course).aggregate(Sum('points'))
        b=CourseReview.objects.filter(course=course).count()

        course.rating=a['points__sum']/b
        course.save()

        return validated_data

class MentorReviewSerializer(serializers.ModelSerializer):
    points=serializers.CharField(max_length=5,allow_blank=True)
    desc=serializers.CharField(max_length=200,allow_blank=True)
    class Meta:
        model=MentorReview
        fields=('points','desc')
#
    def validate(self,data):
        points=data['points']
        desc=data['desc']
        mentor=self.context['mentor']
        ruser=self.context['ruser']


        if not points or points=="":
            raise APIException400({
                'message':'Please provide raing',
                'success':'False',
            })
        if not desc or desc=="":
            raise APIException400({
                'message':'Please write something as review',
                'success':'False',
            })
        if points not in ('1','2','3','4','5'):
            raise APIException400({
                'message':'Please provide rating between 1 to 5',
                'success':'False',
            })

        cr_q=MentorReview.objects.filter(mentor=mentor,user=ruser).first()

        if cr_q:
            raise APIException400({
                'message':'You have already given your review for the mentor.',
                'success':'False',
            })

        return data

    def create(self,validated_data):
        ruser=self.context['ruser']
        mentor=self.context['mentor']
        points=validated_data['points']
        desc=validated_data['desc']
        cr=MentorReview(
            mentor=mentor,
            user=ruser,
            points=points,
            desc=desc,
        )
        cr.save()

        a=MentorReview.objects.filter(mentor=mentor).aggregate(Sum('points'))
        b=MentorReview.objects.filter(mentor=mentor).count()

        mentor.rating=a['points__sum']/b
        mentor.save()

        return validated_data

class VideoReviewSerializer(serializers.ModelSerializer):
    points=serializers.CharField(max_length=5,allow_blank=True)
    desc=serializers.CharField(max_length=200,allow_blank=True)
    class Meta:
        model=VideoReview
        fields=('points','desc')
#
    def validate(self,data):
        points=data['points']
        desc=data['desc']
        video=self.context['video']
        ruser=self.context['ruser']


        if not points or points=="":
            raise APIException400({
                'message':'Please provide raing',
                'success':'False',
            })
        if not desc or desc=="":
            raise APIException400({
                'message':'Please write something as review',
                'success':'False',
            })
        if points not in ('1','2','3','4','5'):
            raise APIException400({
                'message':'Please provide rating between 1 to 5',
                'success':'False',
            })

        vr_q=VideoReview.objects.filter(video=video,user=ruser).first()

        if vr_q:
            raise APIException400({
                'message':'You have already given your review for this video.',
                'success':'False',
            })

        return data

    def create(self,validated_data):
        ruser=self.context['ruser']
        video=self.context['video']
        points=validated_data['points']
        desc=validated_data['desc']
        cr=VideoReview(
            video=video,
            user=ruser,
            points=points,
            desc=desc,
        )
        cr.save()

        a=VideoReview.objects.filter(video=video).aggregate(Sum('points'))
        b=VideoReview.objects.filter(video=video).count()

        video.rating=a['points__sum']/b
        video.save()

        return validated_data

class ReviewListByCourseSerializer(serializers.ModelSerializer):
    class Meta:
        model=CourseReview
        fields='__all__'

class ReviewListByMentorSerializer(serializers.ModelSerializer):
    class Meta:
        model=MentorReview
        fields='__all__'

class ReviewListByVideoSerializer(serializers.ModelSerializer):
    class Meta:
        model=VideoReview
        fields='__all__'
