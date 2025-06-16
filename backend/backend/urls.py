from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from . import views
from rest_framework.routers import DefaultRouter
from .views import (
    DestinosViewSet,
    MetodoPagoViewSet,
    NosotrosViewSet,
    CarritoViewSet, 
    profile_api_view,
    profile_detail_api_view,
    obtener_usuario_autenticado,
    listar_compras, 
    obtener_perfil_usuario,
    checkout,
    LoginView,
    RegisterView,
    token_refresh,
    actualizar_perfil_parcial,
    create_preference, 
    mercadopago_notifications, 
    mercadopago_success, 
    mercadopago_failure, 
    mercadopago_pending,
    ChangePasswordView
)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

router = DefaultRouter()
router.register(r'destinos', DestinosViewSet)
router.register(r'nosotros', NosotrosViewSet)
router.register(r'carrito', CarritoViewSet, basename='carrito') # ESTA LÍNEA ES CLAVE para el carrito
router.register(r'metodos-pago', MetodoPagoViewSet)

# Configuración principal de URLs
urlpatterns = [
    path('admin/', admin.site.urls),
    
    # MERCADO PAGO
    path('api/v1/mercadopago/create_preference/', create_preference, name='create_preference'),
    path('api/v1/mercadopago/notifications/', mercadopago_notifications, name='mercadopago_notifications'),
    path('api/v1/mercadopago/success/', mercadopago_success, name='mercadopago_success'),
    path('api/v1/mercadopago/failure/', mercadopago_failure, name='mercadopago_failure'),
    path('api/v1/mercadopago/pending/', mercadopago_pending, name='mercadopago_pending'),

    # API v1
    path('api/v1/', include([
        # Autenticación
        path('auth/', include([
            path('register/', RegisterView.as_view(), name='register'),
            path('login/', LoginView.as_view(), name='login'),
            path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
            path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
            path('custom-token/refresh/', token_refresh, name='custom_token_refresh'),
        ])),

        # Perfiles
        path('profiles/', include([
            path('', profile_api_view, name='profiles_api'),
            path('<int:pk>/', profile_detail_api_view, name='profiles_detail_api'),
            path('me/update/', actualizar_perfil_parcial, name='actualizar_perfil_parcial'),
            path('me/', obtener_perfil_usuario, name='obtener_perfil'),
            path('me/upload-image/', views.upload_profile_image, name='upload_profile_image'),
            
        ])),
        
        # URL para cambiar contraseña desde el perfil
        path('auth/change-password/', ChangePasswordView.as_view(), name='change_password'),

        # Compras
        path('purchases/', listar_compras, name='listar_compras'),
        path('checkout/', checkout, name='checkout'),

        # Usuario actual
        path('user/me/', obtener_usuario_autenticado, name='obtener_usuario_autenticado'),

        # Router principal (incluye destinos, nosotros, carrito, metodos-pago)
        # /api/v1/carrito/
        # /api/v1/carrito/{pk}/
        # /api/v1/carrito/by_user/{user_id}/ (La acción que necesitas para ver el carrito por usuario)
        # /api/v1/carrito/add_item/ (La acción para agregar/actualizar un ítem)
        path('', include(router.urls)),
    ])),

    # Accounts (recuperación de contraseña)
    path('api/accounts/', include('accounts.urls')),
]

# Servir archivos multimedia en desarrollo
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)