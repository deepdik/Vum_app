from django.db import models

from mentor_panel.or_post.models import *
from mentee_panel.accounts.models import *
from mentor_panel.or_accounts.models import CourseVideo,Course
# Create your models here.
class CourseReview(models.Model):
    course=models.ForeignKey(Course,on_delete=models.CASCADE,related_name='rev_course')
    user=models.ForeignKey(RegisteredUser,on_delete=models.CASCADE,related_name='rev_user')
    points=models.PositiveIntegerField(default=0)
    desc=models.CharField(max_length=200,blank=True)

    def __str__(self):
        return self.course.course_name+' '+self.user.name

class MentorReview(models.Model):
    mentor=models.ForeignKey(RegisteredUser,on_delete=models.CASCADE,related_name='rev_mentor')
    user=models.ForeignKey(RegisteredUser,on_delete=models.CASCADE,related_name='rev_user3')
    points=models.PositiveIntegerField(default=0)
    desc=models.CharField(max_length=200,blank=True)

    def __str__(self):
        return self.mentor.name+' '+self.user.name

class VideoReview(models.Model):
    video=models.ForeignKey(CourseVideo,on_delete=models.CASCADE,related_name='rev_video')
    user=models.ForeignKey(RegisteredUser,on_delete=models.CASCADE,related_name='rev_user4')
    points=models.PositiveIntegerField(default=0)
    desc=models.CharField(max_length=200,blank=True)

    def __str__(self):
        return self.video.video_title+' '+self.user.name
