from django.urls import path
from .views import *

urlpatterns = [
    path('auth/', AuthToken.as_view()),
    path('logout/', Logout.as_view()),
    path('server/', GetServer.as_view()),
    path('server/create/', CreateServer.as_view()),
    path('server/<str:id>/',GetServerById.as_view()),
    path('server/delete/<str:id>/', DeleteServer.as_view()),
    #path('server/status/', ServerStatus.as_view()),
    path('user/', CreateUser.as_view()),
    path('user/<str:id>/', DeleteUser.as_view()),
]