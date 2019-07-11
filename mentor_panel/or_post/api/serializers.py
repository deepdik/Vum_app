from rest_framework import serializers
from rest_framework_jwt.settings import api_settings
from rest_framework.exceptions import APIException
#
from mentee_panel.accounts.models import *
from mentor_panel.or_accounts.models import *
from mentor_panel.or_post.models import *
#
import logging
logger = logging.getLogger('accounts')
#
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER


post_remove_url=serializers.HyperlinkedIdentityField(view_name="or_post:or_post_remove",lookup_field="pk")
add_to_fav_url=serializers.HyperlinkedIdentityField(view_name="or_post:or_post_add_fav",lookup_field="pk")
add_comment_url=serializers.HyperlinkedIdentityField(view_name="or_post:or_post_add_comm",lookup_field="pk")
#
class APIException400(APIException):
    status_code = 400
#
class UploadPostSerializer(serializers.ModelSerializer):
    post_desc=serializers.CharField(max_length=500)
    post_image=serializers.ImageField(required=False)
#
    class Meta:
        model=Post
        fields=('post_desc','post_image')

    def validate(self,data):
        if not post_desc or post_desc=='':
            raise APIException400({
                'message':'Please provide post description',
                'success':'False',
            })
        return data

    def create(self,validated_data):
        post_desc=validated_data['post_desc']
        post_image=self.context['request'].FILES.get('post_image')
        ruser=self.context['request'].user
        ruser=RegisteredUser.objects.filter(user=user).first()

        p=Post(
            user=ruser,
            post_desc=post_desc,
            post_image=post_image,
        )
        p.save()

        validated_data['name']=ruser.name
        validated_data['created_on']=p.created_on
        validated_data['views']=p.views

        return validated_data

class CommentListSerializer(serializers.ModelSerializer):
    user=serializers.SerializerMethodField()
    class Meta:
        model=Post
        fields=('user','comment_desc','created_on')
    def get_user(self,instance):
        ruser=instance.user
        data={}
        data['name']=ruser.name
        data['user_image']=''
        if ruser.profile_image:
            data['user_image']=ruser.profile_image
        return data

class MentorPostListSerializer(serializers.ModelSerializer):
    user=serializers.SerializerMethodField()
    comments=serializers.SerializerMethodField()
    post_remove_url=post_remove_url
    add_to_fav_url=add_to_fav_url
    add_comment_url=add_comment_url

    class Meta:
        model=Post
        fields=('user','post_desc','post_image','created_on','views','likes','comments',
        'post_remove_url','add_to_fav_url','add_comment_url')

    def get_user(self,instance):
        ruser=instance.user
        data={}
        data['name']=ruser.name
        data['user_image']=''
        if ruser.profile_image:
            data['user_image']=ruser.profile_image
        return data
    def get_comments(self,instance):
        queryset=Comment.objects.filter(post=instance)
        serializer=CommentListSerializer(queryset,many=True)
        return serializer.data

class SpecificMentorPostListSerializer(serializers.ModelSerializer):
    mentor_name=serializers.SerializerMethodField()
    mentor_profile_image=serializers.SerializerMethodField()
    comments=serializers.SerializerMethodField()
    post_remove_url=post_remove_url
    add_to_fav_url=add_to_fav_url
    add_comment_url=add_comment_url

    class Meta:
        model=Post
        fields=('mentor_name','mentor_profile_image','post_desc','post_image','created_on','views','likes','comments',
        'post_remove_url','add_to_fav_url','add_comment_url')

    def get_mentor_name(self,instance):
        ruser=instance.user
        return ruser.name
    def get_mentor_profile_image(self,instance):
        ruser=instance.user
        profile_image=''
        if ruser.profile_image:
            profile_image=ruser.profile_image
        return profile_image

    def get_comments(self,instance):
        queryset=Comment.objects.filter(post=instance)
        serializer=CommentListSerializer(queryset,many=True)
        return serializer.data

class CommentPostSerializer(serializers.ModelSerializer):
    user=serializers.CharField(read_only=True)
    comment_desc=serializers.CharField(max_length=200, allow_blank=True)
    created_on=serializers.CharField(read_only=True)
    post_id=serializers.CharField(read_only=True)
    class Meta:
        model=Comment
        fields=('comment_desc','user','created_on','post_id')#,,,'
    def validate(self,data):
        comment_desc=data['comment_desc']
        if not comment_desc or comment_desc=="":
            raise APIException400({
                'message':'Please write your comment',
                'success':'False'
            })
        return data
    def create(self,validated_data):
        comment_desc=validated_data['comment_desc']
        ruser=self.context['ruser']
        post=self.context['post']
        c=Comment(
            user=ruser,
            post=post,
            comment_desc=comment_desc,
        )
        c.save()
        validated_data['user']=ruser.name
        validated_data['created_on']=c.created_on
        validated_data['post_id']=post.id
        return validated_data
