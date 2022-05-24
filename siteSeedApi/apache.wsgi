import os
import sys

path = '/var/www/siteSeedApi'
if path not in sys.path:
    sys.path.insert(0, '/var/www/siteSeedApi')
    sys.path.append('/var/www/siteSeedApi/siteSeedApi')

os.environ['DJANGO_SETTINGS_MODULE'] = 'siteSeedApi.settings'

#import django.core.handlers.wsgi
#application = django.core.handlers.wsgi.WSGIHandler()

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
