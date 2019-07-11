from django.urls import path

from .views import *

app_name='mentee_ex1'

urlpatterns=[
    path('homescreen/',MenteeHomeScreenView.as_view(),name='mentee_ex1_homescreen'),
    path('homescreen/search/',MenteeHomeScreenSearchView.as_view(),name='mentee_ex1_homescreen_search'),
    path('follwing/mentors_list/',FollowingMentorListView.as_view(),name='mentee_ex1_following_mentor_list'),
    path('enrolled/course_list/',EnrolledCourseListView.as_view(),name='mentee_ex1_enrolled_course_list'),
    path('enrolled/course_list/<int:pk>',OpenCourseView.as_view(),name='mentee_ex1_open_course'),
    path('update/video_duration/<int:pk>',UpdateVideoDurationView.as_view(),name='mentee_ex1_update_video_duration'),
]
