from rest_framework.permissions import BasePermission, SAFE_METHODS
from mentee_panel.accounts.models import *

class IsMentor(BasePermission):
    message='You must be a mentor for this operation'
    def has_object_permission(self,request,view,obj):
        ruser_obj=RegisteredUser.onjects.filter(user=request.user).first()
        print(2 == ruser_obj.user_type)
        return '2' == ruser_obj.user_type
