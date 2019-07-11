from django.contrib import admin

from .models import *
# Register your models here.
admin.site.register(CourseReview)
admin.site.register(MentorReview)
admin.site.register(VideoReview)
