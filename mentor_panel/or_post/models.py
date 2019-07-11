from django.db import models

from mentee_panel.accounts.models import RegisteredUser
# Create your models here.
class Post(models.Model):
    user=models.ForeignKey(RegisteredUser,on_delete=models.CASCADE, related_name='puser')
    post_desc=models.CharField(max_length=1000,blank=True)
    post_image=models.ImageField(upload_to='mentor_panel/post')
    created_on=models.DateTimeField(auto_now_add=True)
    views=models.PositiveIntegerField(default=0)
    likes=models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.user.name+'-'+self.post_desc

class Comment(models.Model):
    user=models.ForeignKey(RegisteredUser,on_delete=models.CASCADE,related_name='cuser')
    post=models.ForeignKey(Post,on_delete=models.CASCADE,related_name='cpost')
    comment_desc=models.CharField(max_length=200)
    created_on=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.name+'-'+self.comment_desc

class FavPostList(models.Model):
    user=models.ForeignKey(RegisteredUser,on_delete=models.CASCADE,related_name='fpuser')
    post=models.ForeignKey(Post,on_delete=models.CASCADE,related_name='fppost')
    created_on=models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.name+'-fav post-'+self.post.desc[0:10]
