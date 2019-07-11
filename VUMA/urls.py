"""VumaApp URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from django.conf.urls import url,include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    #silk
    url(r'^silk', include('silk.urls', namespace='silk')),
    #email varification
    url('^', include('django.contrib.auth.urls')),
    #email activation
    # url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',activate, name='activate'),

    #mentee_panel
    path('user/accounts/',include('mentee_panel.accounts.api.urls',namespace='mentee_accounts')),
    path('user/review/',include('mentee_panel.review.api.urls',namespace='mentee_review')),
    path('user/enrollment/',include('mentee_panel.enrollment.api.urls',namespace='mentee_enrollment')),
    path('user/ex1/',include('mentee_panel.extra1.api.urls',namespace='mentee_ex1')),
    #mentor_panel
    path('mentor/accounts/',include('mentor_panel.or_accounts.api.urls',namespace='or_accounts')),
    path('mentor/post/',include('mentor_panel.or_post.api.urls',namespace='or_post')),
    path('mentor/ex1/',include('mentor_panel.or_extra1.api.urls',namespace='or_ex1')),
    #admin_panel

]

if settings.DEBUG:
  urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
