from django.urls import path

from .views import *

app_name='mentee_enrollment'

urlpatterns=[
    path('<int:pk>',EnrollCourseView.as_view(),name='mentee_enrollment_enroll'),
]
