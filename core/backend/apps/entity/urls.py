from django.urls import path
from .views import *

urlpatterns = [
    path('auth/', AuthToken.as_view()),
    path('logout/', Logout.as_view()),
    path('server/', ServerDetail.as_view()),
    path('user/', UserDetail.as_view()),
    path('server/status/', ServerStatus.as_view()),
]