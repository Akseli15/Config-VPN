from django.db import models
from django.contrib import admin

class Server(models.Model):

    _id = models.CharField(verbose_name='ID', max_length=150, default='server_', unique=True)
    ip = models.GenericIPAddressField(verbose_name="Адрес", max_length=50, default='address', unique=True)
    portSSH = models.CharField(verbose_name="SSH порт", max_length=5)
    portWG = models.CharField(verbose_name="WG порт", max_length=5, default=0)
    publicKey = models.CharField(verbose_name="Публичный ключ", max_length=50, default='public_key', unique=True)
    statusServer = models.BooleanField(verbose_name="Статус активности сервера", default=False)
    statusWG = models.BooleanField(verbose_name="Статус активности WG", default=False)

    class Meta:
        verbose_name = 'Сервер'
        verbose_name_plural = 'Серверы'

    def __str__(self):
        return self.ip

class User(models.Model):

    _id = models.CharField(verbose_name='ID', max_length=150, default='user_', unique=True)
    username = models.CharField(verbose_name="Имя пользователя", max_length=50, default='address', unique=True)
    publicKey = models.CharField(verbose_name="Публичный ключ", max_length=50, default='public_key', unique=True)
    allowedIps = models.CharField(max_length=18, verbose_name="Разрешенные IP", default="10.0.0.1/32")

    class Meta:
        verbose_name = 'Пользователь'
        verbose_name_plural = 'Пользователи'

    def __str__(self):
        return self.username


class SystemUser(models.Model):

    _id = models.CharField(verbose_name='ID', max_length=150, default='systemuser_', unique=True)
    login = models.CharField(verbose_name="Логин", max_length=60, unique=True)
    password = models.CharField(verbose_name="Пароль", max_length=60)

    class Meta:
        verbose_name = 'Системный пользователь'
        verbose_name_plural = 'Системные пользователи'

    def __str__(self):
        return self.login

class ServerUser(models.Model):

    _id = models.CharField(verbose_name='ID', max_length=150, default='serveruser_', unique=True)
    login = models.CharField(verbose_name="Логин", max_length=60, unique=True)
    password = models.CharField(verbose_name="Пароль", max_length=60)

    class Meta:
        verbose_name = 'Серверный пользователь'
        verbose_name_plural = 'Серверные пользователи'

    def __str__(self):
        return self.login
