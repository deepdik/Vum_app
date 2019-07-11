from django.urls import path

from .views import *

app_name='or_accounts'

urlpatterns=[
#CATEGORY LIST-------
    path('category/list/',CategoryListView.as_view(),name='ora_cat_list'),
#CATEGORY WISE COURSE DETAIL----------
    path('category/<int:pk>/course_list/',CourseByCategoryListView.as_view(),name='ora_course_by_cat_list'),
    path('category/<int:pk>/popular_course_list/',PopularCourseByCategoryListView.as_view(),name='ora_popular_course_by_cat_list'),
    path('category/course_list/detail/<int:pk>',CourseDetailView.as_view(),name='ora_course_by_cat_detail'),
    path('category/course_list/detail/<int:pk>/wishlist/',AddToWishListView.as_view(),name='ora_course_add_to_wishlist'),

#CATEGORY WISE MENTOR DETAIL----------
    path('category/<int:pk>/mentor_list/',MentorByCategoryListView.as_view(),name='ora_mentor_by_cat_list'),
    path('category/<int:pk>/popular_mentor_list/',PopularMentorByCategoryListView.as_view(),name='ora_popular_mentor_by_cat_list'),
    path('category/mentor_list/detail/<int:pk>',MentorDetailView.as_view(),name='ora_mentor_by_cat_detail'),
    path('<int:pk>/course_list/',CourseByMentorListView.as_view(),name='ora_course_by_mentor_list'),
    path('<int:pk>/followers_list/',FollowersByMentorListView.as_view(),name='ora_followers_by_mentor_list'),
    path('followers_list/',FollowersOfMentorListView.as_view(),name='ora_followers_of_mentor_list'),

#CREATE COURSE
    path('course/create/',AddCourseView.as_view(),name='ora_course_create'),
    path('course/add/video/<int:pk>/',AddVideoView.as_view(),name='ora_course_add_video'),

#ALL COURSE LIST
    path('course/list/',CourseListView.as_view(),name='ora_course_list'),

#ADD TO WISHLIST
    path('course/<int:pk>/wishlist/add/',AddToWishListView.as_view(),name='ora_wishlist_add'),
    path('user/wishlist/',WishListByUserListView.as_view(),name='ora_wishlist'),
]
