from django.urls import path
from .views import *

urlpatterns = [
    path('auth/', AuthToken.as_view()),
    path('logout/', Logout.as_view()),
    path('server/', GetServer.as_view()),
    path('server/', CreateServer.as_view()),
    path('server/<str:id>/', DeleteServer.as_view()),
    path('server/status/', ServerStatus.as_view()),
    path('user/', GetUser.as_view()),
    path('user/', CreateUser.as_view()),
    path('user/<str:id>/', DeleteUser.as_view()),
]