from rest_framework import serializers
from rest_framework_jwt.settings import api_settings
from rest_framework.exceptions import APIException
from django.db.models import Q
# from moviepy.editor import VideoFileClip
import subprocess
# from subprocess import Popen, PIPE
# import re

from mentee_panel.accounts.models import *
from mentee_panel.review.models import *
from mentor_panel.or_accounts.models import *

from mentee_panel.review.api.serializers import *

import logging
logger = logging.getLogger('accounts')

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

all_course_list_url=serializers.HyperlinkedIdentityField(view_name='or_accounts:ora_course_by_cat_list', lookup_field='pk')
popular_course_list_url=serializers.HyperlinkedIdentityField(view_name='or_accounts:ora_popular_course_by_cat_list', lookup_field='pk')
course_detail_url=serializers.HyperlinkedIdentityField(view_name='or_accounts:ora_course_by_cat_detail', lookup_field='pk')
add_to_wishlist_url=serializers.HyperlinkedIdentityField(view_name='or_accounts:ora_wishlist_add', lookup_field='pk')

all_mentor_list_url=serializers.HyperlinkedIdentityField(view_name='or_accounts:ora_mentor_by_cat_list', lookup_field='pk')
popular_mentor_list_url=serializers.HyperlinkedIdentityField(view_name='or_accounts:ora_popular_mentor_by_cat_list', lookup_field='pk')
mentor_detail_url=serializers.HyperlinkedIdentityField(view_name='or_accounts:ora_mentor_by_cat_detail', lookup_field='pk')

review_list_url=serializers.HyperlinkedIdentityField(view_name='mentee_review:mr_list_mentor', lookup_field='pk')
course_list_url=serializers.HyperlinkedIdentityField(view_name='or_accounts:ora_course_by_mentor_list', lookup_field='pk')
followers_list_url=serializers.HyperlinkedIdentityField(view_name='or_accounts:ora_followers_by_mentor_list', lookup_field='pk')
# mentor

class APIException400(APIException):
    status_code = 400

# ,lookup_field='id'

class CategoryListSerializer(serializers.ModelSerializer):
    popular_course_list_url=popular_course_list_url
    popular_mentor_list_url=popular_mentor_list_url
    all_course_list_url=all_course_list_url
    all_mentor_list_url=all_mentor_list_url
    class Meta:
        model=Category
        fields=('id','name','icon','popular_course_list_url','popular_mentor_list_url',
        'all_course_list_url','all_mentor_list_url')

class CourseByFilterListSerializer(serializers.ModelSerializer):
    course_detail_url=course_detail_url
    # def to_representation(self,instance):
    #     data=super().to_representation(instance)
    #     if not data['profile_image']:
    #         data['profile_image']=""
    #         return data
    class Meta:
        model=Course
        fields=('course_cover_image','course_name','course_desc','rating',
        'course_price','course_offered_price','course_detail_url')

class CourseDetailSerializer(serializers.ModelSerializer):
    similar_courses=serializers.SerializerMethodField()
    mentor_name=serializers.SerializerMethodField()
    add_to_wishlist_url=add_to_wishlist_url
    class Meta:
        model=Course
        fields=('course_cover_image','course_name','course_desc','mentor_name',
        'course_price','course_offered_price','add_to_wishlist_url','similar_courses')

    def get_similar_courses(self,instance,*args,**kwargs):
        cat=self.context['cat']
        request=self.context['request']
        cat=Category.objects.filter(name__iexact=cat).first()
        queryset=Course.objects.filter(Q(course_category=cat) & ~Q(id=instance.id))
        return CourseByFilterListSerializer(queryset,many=True,context={'request':request}).data
    def get_mentor_name(self,instance):
        return instance.course_mentor.name

class MentorByFilterListSerializer(serializers.ModelSerializer):
    mentor_detail_url=mentor_detail_url
    class Meta:
        model=RegisteredUser
        fields=('id','name','profession','profile_image','mentor_detail_url','rating')
    def to_representation(self,instance):
        data=super().to_representation(instance)
        if not data['profile_image']:
            data['profile_image']=""
        if not data['profession']:
            data['profession']=""
        if not data['name']:
            data['name']=""
        return data

class MentorDetailSerializer(serializers.ModelSerializer):
    total_number_of_reviews=serializers.SerializerMethodField()
    review_list_url=review_list_url
    total_number_of_courses=serializers.SerializerMethodField()
    course_list_url=course_list_url
    total_number_of_followers=serializers.SerializerMethodField()
    followers_list_url=followers_list_url
    # course_list=serializers.SerializerMethodField()
    class Meta:
        model=RegisteredUser
        fields=('profile_image','name','profession','city','country','rating',
        'total_number_of_reviews','review_list_url','total_number_of_courses',
        'course_list_url','total_number_of_followers','followers_list_url','about_me')
        # 'course_list',
    def get_total_number_of_reviews(self,instance):
        total_review=MentorReview.objects.filter(user=instance).count()
        return total_review

    def get_total_number_of_courses(self,instance):
        total_course=Course.objects.filter(course_mentor=instance).count()
        return total_course

    def get_total_number_of_followers(self,instance):
        total_followers=FollowingList.objects.filter(mentor=instance).count()
        return total_followers

    def to_representation(self,instance):
        data=super().to_representation(instance)
        if not data['profile_image']:
            data['profile_image']=""
        if not data['profession']:
            data['profession']=""
        if not data['city']:
            data['city']=""
        if not data['country']:
            data['country']=""
        return data

class AddCourseSerializer(serializers.ModelSerializer):
    id=serializers.CharField(read_only=True)
    course_cover_image=serializers.ImageField(required=False)
    course_name=serializers.CharField(allow_blank=True)
    course_desc=serializers.CharField(allow_blank=True)
    is_free=serializers.CharField(allow_blank=True)
    course_price=serializers.CharField(allow_blank=True)
    is_certificate=serializers.CharField(allow_blank=True)
    course_category=serializers.CharField(allow_blank=True)

    class Meta:
        model=Course
        fields=('id','course_cover_image','course_name','course_desc','is_free',
        'course_price','is_certificate','course_category')

    def validate(self,data):
        course_cover_image=self.context['request'].FILES.get('course_cover_image')
        course_name=data['course_name']
        course_desc=data['course_desc']
        is_free=data['is_free']
        course_price=data['course_price']
        is_certificate=data['is_certificate']
        course_category=data['course_category']

        # print(course_cover_image)
        if not course_cover_image:
            raise APIException400({
                'message':'course image is required',
                'success':'False',
            })
        if not course_name or course_name=="":
            raise APIException400({
                'message':'course name is required',
                'success':'False',
            })
        if not course_desc or course_desc=="":
            raise APIException400({
                'message':'course desc is required',
                'success':'False',
            })
        if not is_free or course_desc=="":
            raise APIException400({
                'message':'is that course free',
                'success':'False',
            })
        if is_free not in ('0','1'):
            raise APIException400({
                'message':'value of is_free must be either 0 or 1',
                'success':'False',
            })
        if is_free=='0':
            if not course_price or course_price=="":
                raise APIException400({
                    'message':'course price is required',
                    'success':'False',
                })
        if is_free=='1':
            if course_price:
                raise APIException400({
                    'message':'This course is free. So, please check the course price.',
                    'success':'False',
                })
        if not is_certificate or is_certificate=="":
            raise APIException400({
                'message':'is that course need any certificate?',
                'success':'False',
            })
        if is_certificate not in ('0','1'):
            raise APIException400({
                'message':'value of is_certificate must be either 0 or 1',
                'success':'False',
            })
        if not course_category or course_category=="":
            raise APIException400({
                'message':'course category is required',
                'success':'False',
            })
        else:
            cat=Category.objects.filter(id=course_category).first()
            if not cat:
                raise APIException400({
                    'message':'please select a valid category',
                    'success':'False',
                })
        return data

    def create(self,validated_data):
        request=self.context['request']
        course_cover_image=request.FILES.get('course_cover_image')
        course_name=validated_data['course_name']
        course_desc=validated_data['course_desc']
        is_free=validated_data['is_free']
        course_price=validated_data['course_price']
        is_certificate=validated_data['is_certificate']
        course_category=validated_data['course_category']
        user=self.context['user']

        is_free = True if is_free=='0' else False
        is_certificate = True if is_certificate=='0' else False

        cat=Category.objects.filter(id=course_category).first()
        if course_price:
            pass
        else:
            course_price='0.0'
        ruser=RegisteredUser.objects.filter(user=user).first()
        print(course_cover_image)
        if ruser.user_type=='2':
            c=Course(
                course_cover_image=course_cover_image,
                course_name=course_name,
                course_desc=course_desc,
                course_mentor=ruser,
                is_free=is_free,
                course_price=course_price,
                course_offered_price=course_price,
                is_certificate=is_certificate,
                course_category=cat,

            )
            c.save()

        else:
            raise APIException400({
                'message':'You must be a mentor to create a course',
                'success':'False',
            })

        validated_data['course_cover_image']=c.course_cover_image
        validated_data['id']=c.id
        return validated_data

class AddVideoSerializer(serializers.ModelSerializer):
    video_title=serializers.CharField(max_length=100,allow_blank=True)
    video_desc=serializers.CharField(max_length=150,allow_blank=True)
    video_cover_image=serializers.ImageField(required=False)
    video_file=serializers.FileField(required=False)
    video_short_clip=serializers.FileField(required=False)
    video_length_in_seconds=serializers.CharField(read_only=True)

    class Meta:
        model=CourseVideo

        fields=('video_title','video_desc','video_cover_image','video_file',
        'video_short_clip','video_length_in_seconds')

    def to_representation(self,instance):
        data=super().to_representation(instance)
        if not data['video_short_clip']:
            data['video_short_clip']=""
            return data

    def validate(self,data):
        video_title=data['video_title']
        video_desc=data['video_desc']
        video_cover_image=self.context['request'].FILES.get('video_cover_image')
        video_file=self.context['request'].FILES.get('video_file')
        video_short_clip=self.context['request'].FILES.get('video_short_clip')
        # video_length_in_minutes=data['video_length_in_minutes']

        print('hello')
        if not video_title or video_title=='':
            raise APIException400({
                'success':'False',
                'message':'Video title is required',
            })
        if not video_desc or video_desc=='':
            raise APIException400({
                'success':'False',
                'message':'Video description is required',
            })
        if not video_cover_image:
            raise APIException400({
                'success':'False',
                'message':'Video cover image is required',
            })
        if not video_file:
            raise APIException400({
                'success':'False',
                'message':'Video file is required',
            })
        # if not video_length_in_minutes:
        #     raise APIException400({
        #         'success':'False',
        #         'message':'Please provide video length',
        #     })

        return data

    def create(self,validated_data):
        course=self.context['course']
        video_title=validated_data['video_title']
        video_desc=validated_data['video_desc']
        video_cover_image=self.context['request'].FILES.get('video_cover_image')
        video_file=self.context['request'].FILES.get('video_file')
        video_short_clip=self.context['request'].FILES.get('video_short_clip')

        # video_length_in_seconds=0
        # print(video_file.name)
        # print(video_file)
        # clip = VideoFileClip(video_file)
        # print( clip.duration )

        cvtemp=CourseVideo.objects.filter(course=course).order_by('-id').first()
        video_serial_no=1
        if cvtemp:
            video_serial_no=cvtemp.video_serial_no+1
        cv=CourseVideo(
            course=course,
            video_title=video_title,
            video_desc=video_desc,
            video=video_file,
            video_cover_image=video_cover_image,
            video_short_clip=video_short_clip,
            video_serial_no=video_serial_no,
        )
        cv.save()

        u='http://localhost:8000'+cv.video.url ##NEEDS TO CHANGE*************
        result = subprocess.Popen(
            ["ffprobe", u],
            stdout = subprocess.PIPE, stderr = subprocess.STDOUT
        )

        y=[str(x) for x in result.stdout.readlines() if "Duration" in str(x)]
        y=y[0].split(' ')
        q=0
        for w in y:
            if q==1:
                q=w
            if w == "Duration:":
                q=1
        q=q[:-1].split('.')[0].split(':')
        video_length_in_seconds=int(q[0])*60*60+int(q[1])*60+int(q[2])
        cv.video_length_in_seconds=video_length_in_seconds
        cv.save()
        course.total_duration_in_seconds=course.total_duration_in_seconds+video_length_in_seconds
        course.total_number_of_videos=course.total_number_of_videos+1
        course.save()

#DIFFERENT TRIES FOR FINDING VIDEO DURATION------------------------------------
        # for x in result.stdout.readlines():
        #     print(x)
        #     print('********')

        # cmd = "avconv -i %s" % cv.video.url
        # p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
        # di = p.communicate()
        # for line in di:
        #     if line.rfind("Duration") > 0:
        #         duration = re.findall("Duration: (\d+:\d+:[\d.]+)", line)[0]
        #     if line.rfind("Video") > 0:
        #         resolution = re.findall("(\d+x\d+)", line)[0]
        # print(duration,resolution)

        # u='http://localhost:8000'+cv.video.url
        # print(u)
        # task = subprocess.Popen("avconv -i "+u+" 2>&1 | grep Duration | cut -d ' ' -f 4 | sed -r 's/([^\.]*)\..*/\1/'", shell=True, stdout=subprocess.PIPE)
        # time = task.communicate()[0]
        # print(task.communicate())
#-------------------------------------------------------------------------------


        validated_data['video_cover_image']=cv.video_cover_image
        validated_data['video_file']=cv.video
        validated_data['video_short_clip']=cv.video_short_clip
        validated_data['video_length_in_seconds']=cv.video_length_in_seconds
        return validated_data

class CourseListSerializer(serializers.ModelSerializer):
    class Meta:
        model=Course
        fields='__all__'

class FollowingListSerializer(serializers.ModelSerializer):
    mentor_name=serializers.SerializerMethodField()
    mentee_name=serializers.SerializerMethodField()
    class Meta:
        model=FollowingList
        fields=('mentor_name','mentee_name')
    def get_mentor_name(self,instance):
        return instance.mentor.name
    def get_mentee_name(self,instance):
        return instance.mentee.name

class WishListByUserListSerializer(serializers.ModelSerializer):
    course_detail_url=course_detail_url
    user=serializers.SerializerMethodField()
    course=serializers.SerializerMethodField()
    class Meta:
        model=WishList
        fields=('course_detail_url','user','course')

    def get_user(self,instance):
        return instance.user.name

    def get_course(self,instance):
        return instance.course.course_name
