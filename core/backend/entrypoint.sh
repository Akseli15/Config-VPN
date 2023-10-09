#!/bin/sh

if [ "$DATABASE" = "postgres" ]
then
    echo "Дожидаемся запуска базы данных..."

    while ! nc -z $SQL_HOST $SQL_PORT; do
      sleep 0.1
    done

    echo "Ну вот и дождались!"
fi

# ./manage.py dumpdata datasets > datasets.json
# python manage.py flush --noinput
# ./manage.py loaddata datasets.json
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser --username root --noinput
# python manage.py collectstatic --noinput --clear
python -m gunicorn config.wsgi:application --bind 0.0.0.0:8000

exec "$@"
