#!/bin/bash
cd /home/bugbount/app
source /home/bugbount/virtualenv/app/3.11/bin/activate
python manage.py migrate
python manage.py collectstatic --noinput
