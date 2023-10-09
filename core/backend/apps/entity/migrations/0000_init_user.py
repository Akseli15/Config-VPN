import logging
from django.db import migrations
from django.contrib.auth import get_user_model

logger = logging.getLogger(__name__)

VPN_USERNAME = 'VPNadmin'
VPN_PASSWORD = 'not_vpn_at_all'
VPN_EMAIL = 'vpn@notvpnatall.ru'


def add_users(apps, schema_editor):

    def create_user(username, password, email):

        user = get_user_model()

        if not user.objects.filter(username=username, email=email).exists():
            logger.info(f"Creating user {username}")

            new_user = user.objects.create_superuser(
                username=username, password=password, email=email
            )

            new_user.save()
        else:
            logger.info(f"{username} already exists!")

    create_user(VPN_USERNAME, VPN_PASSWORD, VPN_EMAIL)


class Migration(migrations.Migration):

    operations = [
        migrations.RunPython(add_users, reverse_code=migrations.RunPython.noop)
    ]
