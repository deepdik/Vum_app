from django.db import models
from django.contrib.auth.models import User
from django.utils.text import slugify


from mentor_panel.or_accounts.models import Category,Background,Course

# Create your models here.

gender_choices=(('1','Male'),('2','Female'))
login_type_choices=(('1','Normal'),('2','Facebook'),('3','Google'))
device_type_choices=(('1','Android'),('2','Ios'),('3','Web'))
user_type_choices=(('1','Mentee'),('2','Mentor'))

class RegisteredUser(models.Model):
    name=models.CharField(max_length=50,null=True,blank=True,)
    profile_image=models.ImageField(upload_to='mentee_panel/profile',blank=True,null=True,)
    age=models.PositiveIntegerField(default=0)
    country_code=models.CharField(max_length=5,null=True,blank=True,)
    mobile=models.CharField(max_length=15,null=True,blank=True,)
    alt_mobile_country_code=models.CharField(max_length=5,null=True,blank=True,)
    alt_mobile=models.CharField(max_length=15,null=True,blank=True,)
    gender=models.CharField(max_length=10,choices=gender_choices,blank=True,null=True,)
    profession=models.CharField(max_length=30,null=True,blank=True)
    building_num=models.CharField(max_length=100,null=True,blank=True)
    locality=models.CharField(max_length=200,null=True,blank=True)
    landmark=models.CharField(max_length=100,null=True,blank=True)
    city=models.CharField(max_length=50,null=True,blank=True)
    country=models.CharField(max_length=50,null=True,blank=True)
    postal_code=models.CharField(max_length=20,null=True,blank=True)

    is_email_verified=models.BooleanField(default=False)
    is_mobile_verified=models.BooleanField(default=False)

    login_type=models.CharField(max_length=10,choices=login_type_choices)
    social_id=models.CharField(max_length=200,blank=True,null=True)
    device_type=models.CharField(max_length=10,choices=device_type_choices)
    device_token=models.CharField(max_length=200,blank=True,null=True)
    user_type=models.CharField(max_length=20,choices=user_type_choices)

    created_on=models.DateTimeField(auto_now_add=True)

    user=models.ForeignKey(User,on_delete=models.CASCADE,related_name='ruser')

# MENTOR SPECIFICS----------------------------------
    category=models.ForeignKey(Category,on_delete=models.SET_NULL,related_name='ru_category',null=True,blank=True)
    declaration=models.FileField(upload_to='mentor_panel/declaration',null=True,blank=True)
    background=models.ForeignKey(Background,on_delete=models.SET_NULL,related_name='ru_background',null=True,blank=True)
    experience=models.CharField(max_length=80,null=True,blank=True)
    about_me=models.TextField(blank=True,null=True)

    rating=models.PositiveIntegerField(default=0)

    slug = models.SlugField(default='')

    def __str__(self):
        return self.user.first_name+'-'+self.mobile
    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        super(RegisteredUser, self).save(*args, **kwargs)

class FollowingList(models.Model):
    mentor=models.ForeignKey(RegisteredUser,on_delete=models.CASCADE,related_name="f_mentor")
    mentee=models.ForeignKey(RegisteredUser,on_delete=models.CASCADE,related_name="f_mentee")
    floowing_from=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return 'mentor:'+self.mentor.name+' mentee:'+self.mentee.name

class WishList(models.Model):
    user=models.ForeignKey(RegisteredUser,on_delete=models.CASCADE,related_name='w_user')
    course=models.ForeignKey(Course,on_delete=models.CASCADE,related_name='w_course')

    def __str__(self):
        return self.user.name+'-'+self.course.course_name
