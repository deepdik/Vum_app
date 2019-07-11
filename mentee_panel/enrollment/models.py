from django.db import models

from mentee_panel.accounts.models import *
from mentor_panel.or_accounts.models import *
# Create your models here.

course_status_choices=(('1','Start'),('2','In Progress'),('3','Completed'),('4','Refund Requested'),('5','Refunded'))
video_status_choices=(('1','Not Played'),('2','In Progress'),('3','Completed'))

class MenteeCourseRegistration(models.Model):
    mentee=models.ForeignKey(RegisteredUser,on_delete=models.CASCADE,related_name='cour_reg_mentee')
    course=models.ForeignKey(Course,on_delete=models.CASCADE,related_name='cour_reg_course')
    status=models.CharField(max_length=20,choices=course_status_choices,blank=True, default='Start')
    total_duration=models.PositiveIntegerField(default=0)
    duration_completed=models.PositiveIntegerField(default=0)
    duration_left=models.PositiveIntegerField(default=0)

    last_video_watched=models.ForeignKey(CourseVideo,on_delete=models.CASCADE,related_name='cour_reg_video')
    # last_video_watched_duration=models.PositiveIntegerField(default=0)
    # is_video_watched_fully=models.BooleanField(default=False)

    def __str__(self):
        return self.mentee.name+'-'+self.course.course_name

class VideoWatchList(models.Model):
    mentee=models.ForeignKey(RegisteredUser,on_delete=models.CASCADE,related_name='vwl_mentee')
    course=models.ForeignKey(Course,on_delete=models.CASCADE,related_name='vwl_course')
    video=models.ForeignKey(CourseVideo,on_delete=models.CASCADE,related_name='vwl_video')
    video_serial_no=models.PositiveIntegerField(default=1)
    video_status=models.CharField(max_length=20,choices=video_status_choices,blank=True,default='Not Played')
    video_watch_duration=models.PositiveIntegerField(default=0)
    video_total_duration=models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.mentee.name+'-'+self.video.video_title
