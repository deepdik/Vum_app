from django.db import models
from django.utils.text import slugify
from datetime import datetime
from decimal import Decimal

# Create your models here.
class Category(models.Model):
    name=models.CharField(max_length=20,)
    icon=models.ImageField(upload_to='mentor_panel/category')
    slug=models.SlugField(default='',)

    def __str__(self):
        return self.name

    def save(self,*args,**kwargs):
        self.slug=slugify(self.name)
        super(Category,self).save(*args,**kwargs)

class SubCategory(models.Model):
    name=models.CharField(max_length=20,)
    category=models.ForeignKey(Category,on_delete=models.CASCADE,related_name='sc_category',)
    icon=models.ImageField(upload_to='mentor_panel/subcategory')
    slug=models.SlugField(default='',)

    def __str__(self):
        return self.name

    def save(self,*args,**kwargs):
        self.slug=slugify(self.name)
        super(SubCategory,self).save(*args,**kwargs)

class Background(models.Model):
    name=models.CharField(max_length=70,)

    def __str__(self):
        return self.name

class Course(models.Model):
    course_cover_image=models.ImageField(upload_to='mentor_panel/course/cover_image')
    course_name=models.CharField(max_length=100,)
    course_desc=models.CharField(max_length=700)
    course_mentor=models.ForeignKey('accounts.RegisteredUser',on_delete=models.CASCADE,related_name='c_mentor')
    is_free=models.BooleanField(default=False)
    course_price= models.DecimalField(max_digits=10, decimal_places=2,default='0.00')
    course_offer=models.PositiveIntegerField(default=0)
    course_offered_price=models.DecimalField(max_digits=10, decimal_places=2,default='0.00')
    is_certificate=models.BooleanField(default=False)
    course_category=models.ForeignKey(Category,on_delete=models.CASCADE,related_name='c_category')
    created_on=models.DateTimeField(auto_now_add=True)
    approved=models.BooleanField(default=False)
    active=models.BooleanField(default=False)
    total_duration_in_seconds=models.PositiveIntegerField(default=0)
    total_number_of_videos=models.PositiveIntegerField(default=0)
    rating=models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.course_name

class Certificate(models.Model):
    cert_name=models.CharField(max_length=50)
    cert=models.FileField(upload_to='mentor_panel/certificate')
    cert_desc=models.CharField(max_length=100)
    course=models.ForeignKey(Course,on_delete=models.CASCADE,related_name='cert_course')
    created_on=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.cert_name

class CourseVideo(models.Model):
    course=models.ForeignKey(Course,on_delete=models.CASCADE,related_name='cr_course')
    video_serial_no=models.PositiveIntegerField(default=0)
    video_title=models.CharField(max_length=100,blank=True,)
    video_desc=models.CharField(max_length=150,blank=True,)
    video=models.FileField(upload_to='mentor_panel/course/video')
    video_short_clip=models.FileField(upload_to='mentor_panel/course/video/video_short_clip')
    video_cover_image=models.ImageField(upload_to='mentor_panel/course/video/video_cover_image')
    created_on=models.DateTimeField(auto_now_add=True,)
    video_length_in_seconds=models.PositiveIntegerField(default=0)
    rating=models.PositiveIntegerField(default=0)


    def __str__(self):
        return self.video_title
