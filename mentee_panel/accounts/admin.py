from django.contrib import admin

from .models import *
# Register your models here.
admin.site.register(RegisteredUser)
admin.site.register(FollowingList)
admin.site.register(WishList)
