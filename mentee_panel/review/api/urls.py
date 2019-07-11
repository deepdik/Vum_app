from django.urls import path

from .views import *

app_name="mentee_review"

urlpatterns=[
    path('course/<int:pk>',CourseReviewView.as_view(),name='mr_course'),
    path('mentor/<int:pk>',MentorReviewView.as_view(),name='mr_mentor'),
    path('video/<int:pk>',VideoReviewView.as_view(),name='mr_video'),

    path('course/<int:pk>/list/',ReviewListByCourseView.as_view(),name='mr_list_course'),
    path('mentor/<int:pk>/list/',ReviewListByMentorView.as_view(),name='mr_list_mentor'),
    path('video/<int:pk>/list/',ReviewListByVideoView.as_view(),name='mr_list_video'),
]
