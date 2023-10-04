from django.contrib import admin
from .models import *

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'allowedIps', )
    # readonly_fields = ()
    # list_filter = ()
    # search_fields = ()
    # actions = []

@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = ('ip', 'statusServer', 'statusWG', )
    # readonly_fields = ()
    # list_filter = ()
    # search_fields = ()
    # actions = []

@admin.register(ServerUser)
class ServerUserAdmin(admin.ModelAdmin):
    list_display = ('login', )
    # readonly_fields = ()
    # list_filter = ()
    # search_fields = ()
    # actions = []

@admin.register(SystemUser)
class SystemUserAdmin(admin.ModelAdmin):
    list_display = ('login', )
    # readonly_fields = ()
    # list_filter = ()
    # search_fields = ()
    # actions = []