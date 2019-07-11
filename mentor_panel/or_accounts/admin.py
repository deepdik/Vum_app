from django.contrib import admin

from .models import *
# Register your models here.
admin.site.register(Category)
admin.site.register(SubCategory)
admin.site.register(Background)
admin.site.register(Course)
admin.site.register(Certificate)
admin.site.register(CourseVideo)
