from django.urls import path

from .views import *

app_name='or_ex1'

urlpatterns=[
    path('homescreen/',MentorHomeScreenView.as_view(),name='or_home'),
    path('homescreen/search/',MentorHomeScreenSearchView.as_view(),name='or_home_search'),
]
