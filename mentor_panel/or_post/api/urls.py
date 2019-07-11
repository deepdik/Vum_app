from django.urls import path

from .views import *

app_name='or_post'

urlpatterns=[
    path('create/',UploadPostView.as_view(),name='or_post_create'),
    path('list/',MentorOwnPostListView.as_view(),name='or_post_list'),
    path('list/<int:pk>',SpecificMentorPostListView.as_view(),name='or_specific_post_list'),
    path('follow/list/',FollowingMentorPostListView.as_view(),name='or_following_post_list'),
    path('remove/<int:pk>',RemovePostView.as_view(),name='or_post_remove'),
    path('add_fav/<int:pk>',AddFavouritePostView.as_view(),name='or_post_add_fav'),
    path('add_comm/<int:pk>',CommentPostView.as_view(),name='or_post_add_comm'),
]
