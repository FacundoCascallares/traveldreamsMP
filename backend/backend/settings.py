from pathlib import Path
import os
from decouple import config
from datetime import timedelta # Importa timedelta para la configuración de JWT

from dotenv import load_dotenv
load_dotenv()

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'un-valor-realmente-secreto-y-unico-para-produccion-aqui-ej-generado-por-django')

# === CONFIGURACIÓN BASE (APLICABLE A AMBOS ENTORNOS) ===
# Application definition
INSTALLED_APPS = [
    'corsheaders',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'accounts.apps.AccountsConfig',
    'core',
]

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Internationalization
LANGUAGE_CODE = 'es-ar'
TIME_ZONE = 'America/Buenos_Aires'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files (Archivos subidos por los usuarios, como imágenes de destinos)
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    # Esto hace que todas las API requieran autenticación por defecto,
    # a menos que se anule en el ViewSet específico (ej. con AllowAny)
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

# Configuración de Django REST Framework Simple JWT
SIMPLE_JWT = {
    # Duración del token de acceso (se recomienda que sea corta por seguridad)
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15), # Aumentado de 5 a 15 minutos, un buen balance
    # Duración del token de refresco (para obtener nuevos tokens de acceso)
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),   # Aumentado a 7 días
    'ROTATE_REFRESH_TOKENS': True, # Se recomienda rotar los tokens de refresco
    'BLACKLIST_AFTER_ROTATION': True, # Y poner en la lista negra los antiguos
    'UPDATE_LAST_LOGIN': False,

    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY, 
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'JWK_URL': None,
    'LEEWAY': 0,

    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'TOKEN_USER_CLASS': 'rest_framework_simplejwt.models.TokenUser',

    'JTI_CLAIM': 'jti',

    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(minutes=5),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1),
}


# Credenciales de Mercado Pago
MERCADOPAGO_ACCESS_TOKEN = os.getenv('MERCADOPAGO_ACCESS_TOKEN')
MERCADOPAGO_PUBLIC_KEY = os.getenv('MERCADOPAGO_PUBLIC_KEY')


# === CONFIGURACIÓN ESPECÍFICA PARA PRODUCCIÓN (PythonAnywhere) ===
if 'PYTHONANYWHERE_DOMAIN' in os.environ:
    DEBUG = False
    ALLOWED_HOSTS = [
        'dreamtravelmp.pythonanywhere.com/',
        'www.dreamtravelmp.pythonanywhere.com',
        os.environ.get('PYTHONANYWHERE_DOMAIN', ''),
        f"www.{os.environ.get('PYTHONANYWHERE_DOMAIN', '')}"
    ]
    
    # Define BACKEND_BASE_URL para producción
    # ¡CAMBIO CRÍTICO! Debe ser la URL del BACKEND en producción, no la del frontend.
    BACKEND_BASE_URL = 'https://dreamtravel.pythonanywhere.com/' 

    # CORS Settings (para PRODUCCIÓN en PythonAnywhere)
    CORS_ALLOWED_ORIGINS = [
        "https://tu-frontend.pythonanywhere.com", # Reemplaza con dominio REAL del frontend en producción
    ]
    CORS_EXPOSE_HEADERS = ['Content-Type', 'X-CSRFToken', 'Authorization'] # Añadido Authorization
    CORS_ALLOW_CREDENTIALS = True
    CORS_ALLOW_METHODS = [
        'DELETE', 'GET', 'OPTIONS', 'PATCH', 'POST', 'PUT',
    ]
    CORS_ALLOW_HEADERS = [
        'accept', 'accept-encoding', 'authorization', 'content-type', 'dnt',
        'origin', 'user-agent', 'x-csrftoken', 'x-requested-with',
    ]
    
    # Security Headers (para PRODUCCIÓN)
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    X_FRAME_OPTIONS = 'DENY'
    
# === CONFIGURACIÓN ESPECÍFICA PARA DESARROLLO LOCAL ===
else: # Esto se ejecuta cuando 'PYTHONANYWHERE_DOMAIN' NO está en os.environ (es decir, en local)
    DEBUG = False
    ALLOWED_HOSTS = [
        'localhost',
        '127.0.0.1',
        # 'caf4-201-179-84-139.ngrok-free.app', # Descomentar y actualizar si usamos ngrok
    ]

    # CORS Settings (para DESARROLLO local)
    CORS_ALLOWED_ORIGINS = [
        "http://localhost:4200",
        "http://127.0.0.1:4200", 
        # Si usas ngrok, asegúrate de añadir su URL dinámica aquí (ej. "https://caf4-201-179-84-139.ngrok-free.app")
    ]
    CORS_EXPOSE_HEADERS = ['Content-Type', 'X-CSRFToken', 'Authorization'] # Añadido Authorization
    CORS_ALLOW_CREDENTIALS = True
    CORS_ALLOW_ALL_ORIGINS = True # Más permisivo para desarrollo, CUIDADO en producción
    CORS_ALLOW_METHODS = [
        'DELETE', 'GET', 'OPTIONS', 'PATCH', 'POST', 'PUT',
    ]
    CORS_ALLOW_HEADERS = [
        'accept', 'accept-encoding', 'authorization', 'content-type', 'dnt',
        'origin', 'user-agent', 'x-csrftoken', 'x-requested-with',
    ]

    # Security Headers (para DESARROLLO)
    SECURE_PROXY_SSL_HEADER = None 
    SESSION_COOKIE_SECURE = False 
    CSRF_COOKIE_SECURE = False
    SECURE_SSL_REDIRECT = False
    SECURE_HSTS_SECONDS = 0
    SECURE_HSTS_INCLUDE_SUBDOMAINS = False
    SECURE_HSTS_PRELOAD = False
    X_FRAME_OPTIONS = 'SAMEORIGIN' # Cambiado a SAMEORIGIN para compatibilidad en desarrollo

# BASE URLs for your frontend and backend (for Mercado Pago callbacks/redirects)
FRONTEND_BASE_URL = 'http://localhost:4200' # O la URL de tu frontend en producción
BACKEND_BASE_URL = 'http://127.0.0.1:8000' # O la URL de tu backend en producción

# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True

EMAIL_HOST_USER = config('EMAIL_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_PASSWORD')
DEFAULT_FROM_EMAIL = f'TravelDreams <{EMAIL_HOST_USER}>'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'accounts': { # Agrega un logger para tu aplicación 'accounts'
            'handlers': ['console'],
            'level': 'DEBUG', # Configúralo en DEBUG para ver los mensajes detallados
            'propagate': False,
        },
        'backend': { # Si tus views.py están en 'backend'
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        }
    },
    'root': {
        'handlers': ['console'],
        'level': 'DEBUG', # Puedes ponerlo en DEBUG para ver todo
    }
}