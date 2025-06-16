from rest_framework import viewsets, generics, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from accounts.models import Destinos, Carrito, Nosotros, User, MetodoPago, Profile
from .serializers import (
    DestinosSerializer,
    MetodoPagoSerializer,
    CarritoSerializer,
    NosotrosSerializer,
    ProfileSerializer,
    RegisterSerializer,
    LoginSerializer,
    ChangePasswordSerializer
)
from django.contrib.auth.models import User
import logging
from rest_framework import serializers

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import mercadopago
import json
import uuid
from django.db import transaction
from django.utils import timezone
from datetime import date

# SDK DE MERCADO PAGO
sdk = mercadopago.SDK(settings.MERCADOPAGO_ACCESS_TOKEN)

logger = logging.getLogger(__name__)

# ---
## MetodoPagoViewSet (Público)
# ---
class MetodoPagoViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = MetodoPago.objects.all()
    serializer_class = MetodoPagoSerializer
    permission_classes = [AllowAny] 

# ---
## NosotrosViewSet (Público para list, Protegido para CRUD)
# ---
class NosotrosViewSet(viewsets.ModelViewSet):
    queryset = Nosotros.objects.all()
    serializer_class = NosotrosSerializer

    def get_permissions(self):
        if self.action == 'list' or self.action == 'retrieve':
            self.permission_classes = [AllowAny]
        else:
            self.permission_classes = [IsAuthenticated]
        return super().get_permissions()

    def create(self, request, *args, **kwargs):
        logger.debug('Creating a new Nosotros entry')
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        logger.debug(f'Nosotros created successfully: {serializer.data}')
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        logger.debug(f'Updating Nosotros with id: {instance.id_nosotros}')
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}

        logger.debug(f'Nosotros updated successfully: {serializer.data}')
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        logger.debug(f'Deleting Nosotros with id: {instance.id_nosotros}')
        self.perform_destroy(instance)
        logger.debug('Nosotros deleted successfully')
        return Response(status=status.HTTP_204_NO_CONTENT)

# ---
## DestinosViewSet (Público para list, Protegido para CRUD)
# ---
class DestinosViewSet(viewsets.ModelViewSet):
    queryset = Destinos.objects.all()
    serializer_class = DestinosSerializer

    def get_permissions(self):
        if self.action == 'list' or self.action == 'retrieve':
            self.permission_classes = [AllowAny]
        else:
            self.permission_classes = [IsAuthenticated]
        return super().get_permissions()

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        logger.debug(f'Updating Destino with id: {instance.id_destino}')
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}

        logger.debug(f'Destino updated successfully: {serializer.data}')
        return Response(serializer.data)

# ---
## CarritoViewSet (Protegido)
# ---
class CarritoViewSet(viewsets.ModelViewSet):
    queryset = Carrito.objects.all()
    serializer_class = CarritoSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Carrito.objects.filter(user=self.request.user).exclude(estado_pago='approved').order_by('-fecha_creacion')

    @action(detail=False, methods=['get'], url_path='by_user/(?P<user_id>\d+)')
    def by_user(self, request, user_id=None):
        if not user_id:
            return Response({"detail": "User ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if request.user.id != int(user_id) and not request.user.is_staff:
            return Response({"detail": "No tienes permiso para ver este carrito."}, status=status.HTTP_403_FORBIDDEN)

        carrito_items = Carrito.objects.filter(user_id=user_id).exclude(estado_pago='approved').order_by('-fecha_creacion')
        serializer = self.get_serializer(carrito_items, many=True)
        return Response(serializer.data)

    # Acción para agregar o actualizar un ítem al carrito
    @action(detail=False, methods=['post'], url_path='add_item')
    def add_item(self, request):
        try:
            id_destino = request.data.get('id_destino')
            cantidad_a_agregar = int(request.data.get('cantidad', 1)) # Convertir a int de forma segura
            fecha_salida_str = request.data.get('fecha_salida')
            id_metodo_pago = request.data.get('id_metodoPago')

            if not id_destino:
                return Response({'error': 'id_destino es requerido'}, status=status.HTTP_400_BAD_REQUEST)

            destino = Destinos.objects.get(pk=id_destino)
            
            metodo_pago = None
            if id_metodo_pago:
                try:
                    metodo_pago = MetodoPago.objects.get(pk=id_metodo_pago)
                except MetodoPago.DoesNotExist:
                    return Response({'error': 'Método de pago no encontrado.'}, status=status.HTTP_404_NOT_FOUND)
            
            fecha_salida = None
            if fecha_salida_str:
                try:
                    fecha_salida = date.fromisoformat(fecha_salida_str)
                except ValueError:
                    return Response({'error': 'Formato de fecha_salida inválido. Usa-MM-DD.'}, status=status.HTTP_400_BAD_REQUEST)
            
            with transaction.atomic(): # Inicia una transacción atómica para asegurar la consistencia
                cart_item = None
                try:
                    # Intenta encontrar un ítem existente en el carrito activo del usuario para este destino y fecha
                    cart_item = Carrito.objects.get(
                        user=request.user, 
                        id_destino=destino, 
                        fecha_salida=fecha_salida, 
                        estado_pago='cart_active'
                    )
                    # Si el ítem existe, calculamos la nueva cantidad total
                    total_nueva_cantidad = cart_item.cantidad + cantidad_a_agregar
                except Carrito.DoesNotExist:
                    # Si no existe, la nueva cantidad total es solo la cantidad a agregar
                    total_nueva_cantidad = cantidad_a_agregar
                
                # --- Lógica de Validación de Stock (CRÍTICA) ---
                if total_nueva_cantidad > destino.cantidad_Disponible:
                    # Si la cantidad total excede la disponibilidad del destino, devuelve un error 400
                    return Response(
                        {
                            'error': {'cantidad': [f"Solo quedan {destino.cantidad_Disponible} cupos disponibles para {destino.nombre_Destino}."]},
                            'detail': f"No hay suficiente stock disponible para {destino.nombre_Destino}. Cantidad máxima: {destino.cantidad_Disponible}"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Si la validación de stock es exitosa, procede a crear o actualizar el ítem
                if cart_item:
                    # Si el ítem ya existía, actualiza su cantidad
                    cart_item.cantidad = total_nueva_cantidad
                    cart_item.save()
                    return Response(self.get_serializer(cart_item).data, status=status.HTTP_200_OK)
                else:
                    # Si el ítem no existía, crea uno nuevo
                    new_cart_item = Carrito.objects.create(
                        user=request.user,
                        id_destino=destino,
                        id_metodoPago=metodo_pago,
                        cantidad=cantidad_a_agregar, # Aquí usamos la cantidad que se pidió AGREGAR (no el total)
                        fecha_salida=fecha_salida,
                        estado_pago='cart_active'
                    )
                    return Response(self.get_serializer(new_cart_item).data, status=status.HTTP_201_CREATED)

        except Destinos.DoesNotExist:
            return Response({'error': 'Destino no encontrado'}, status=status.HTTP_404_NOT_FOUND)
        except ValueError: # Captura si la conversión de 'cantidad' a int falla
            return Response({'error': 'La cantidad debe ser un número entero válido.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error al agregar/actualizar ítem en el carrito: {e}", exc_info=True)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def destroy(self, request, pk=None):
        try:
            carrito_item = self.get_object() 
            
            if carrito_item.user != request.user:
                return Response({'error': 'No tienes permiso para eliminar este ítem.'}, status=status.HTTP_403_FORBIDDEN)
            
            self.perform_destroy(carrito_item)
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Carrito.DoesNotExist:
            return Response({'error': 'Ítem del carrito no encontrado'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error al eliminar ítem del carrito: {e}", exc_info=True)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def partial_update(self, request, pk=None):
        carrito_item = self.get_object()
        
        if carrito_item.user != request.user:
            return Response({'error': 'No tienes permiso para actualizar este ítem.'}, status=status.HTTP_403_FORBIDDEN)

        # Usamos el serializador para la validación y guardado
        # Si la validación falla, serializer.is_valid(raise_exception=True)
        # lanzará una rest_framework.exceptions.ValidationError
        # que Django REST Framework manejará automáticamente, devolviendo un 400 Bad Request.
        serializer = self.get_serializer(carrito_item, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True) 
        serializer.save() 
        return Response(serializer.data, status=status.HTTP_200_OK)


# --- ELIMINAR ESTAS FUNCIONES, SERÁN REEMPLAZADAS POR CARRITOVIEWSET ---
# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def agregar_al_carrito(request):
#    ... ELIMINAR ...

# @api_view(['GET'])
# @permission_classes([IsAuthenticated])
# def obtener_carrito(request):
#    ... ELIMINAR ...

# @api_view(['DELETE'])
# @permission_classes([IsAuthenticated])
# def eliminar_item_carrito(request, id):
#    ... ELIMINAR ...

# @api_view(['PUT'])
# def actualizar_fecha_salida(request, id):
#    ... ELIMINAR ...

# ---
## Dashboard (Protegido)
# ---
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listar_compras(request):
    compras = Carrito.objects.filter(user=request.user, estado_pago='approved').order_by('-fecha_compra')
    serializer = CarritoSerializer(compras, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def obtener_perfil_usuario(request):
    try:
        profile = Profile.objects.get(user=request.user)
        serializer = ProfileSerializer(profile)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Profile.DoesNotExist:
        return Response({'error': 'Perfil no encontrado.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
# CARGA DE IMAGEN DE PERFIL   
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upload_profile_image(request):
    logger.debug(f"[{timezone.now()}] --- Inicia upload_profile_image para usuario {request.user.email} ---")
    try:
        profile = Profile.objects.get(user=request.user)
        logger.debug(f"[{timezone.now()}] Perfil encontrado: {profile.pk}")
        
        image_file = request.FILES.get('image') 
        logger.debug(f"[{timezone.now()}] Archivo de imagen recibido: {'Sí' if image_file else 'No'}")
        if image_file:
            logger.debug(f"[{timezone.now()}] Nombre del archivo: {image_file.name}, Tamaño: {image_file.size} bytes, Tipo: {image_file.content_type}")

        if not image_file:
            logger.warning(f"[{timezone.now()}] No se proporcionó ningún archivo de imagen para el usuario {request.user.email}.")
            return Response({'error': 'No se proporcionó ningún archivo de imagen.'}, status=status.HTTP_400_BAD_REQUEST)

        # Asigna la imagen al campo ImageField del modelo Profile
        profile.image = image_file # CORRECCIÓN: Usar 'image'
        logger.debug(f"[{timezone.now()}] Intentando guardar el perfil para el usuario {request.user.email}...")
        profile.save() # Aquí es donde se realiza la operación de guardado del archivo.
        logger.debug(f"[{timezone.now()}] Perfil guardado exitosamente para {request.user.email}.")

        # Después de guardar, la URL del archivo debería estar disponible.
        image_url = request.build_absolute_uri(profile.image.url) # CORRECCIÓN: Usar 'image.url'
        logger.debug(f"[{timezone.now()}] URL de la imagen de perfil generada: {image_url}")

        return Response({'message': 'Imagen de perfil actualizada exitosamente.', 'imageUrl': image_url}, status=status.HTTP_200_OK)
    except Profile.DoesNotExist:
        logger.error(f"[{timezone.now()}] Perfil no encontrado para el usuario {request.user.email}. Retornando 404.", exc_info=True)
        return Response({'error': 'Perfil no encontrado para el usuario actual.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        # Aquí capturamos cualquier otra excepción durante el proceso
        logger.error(f"[{timezone.now()}] Error al subir imagen de perfil para el usuario {request.user.email}: {str(e)}", exc_info=True)
        return Response({'error': 'Ocurrió un error al subir la imagen. Por favor, inténtelo de nuevo.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ---
## Checkout (Protegido)
# ---
@api_view(['POST'])
@permission_classes([IsAuthenticated]) 
def checkout(request):
    try:
        carrito_items = Carrito.objects.filter(user=request.user, estado_pago='cart_active') 
        metodo_pago_id = request.data.get('metodo_pago')

        if not metodo_pago_id:
            return Response({'error': 'Método de pago es requerido.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            metodo_pago = MetodoPago.objects.get(pk=metodo_pago_id)
        except MetodoPago.DoesNotExist:
            return Response({'error': 'Método de pago no válido.'}, status=status.HTTP_400_BAD_REQUEST)

        if not carrito_items.exists():
            return Response({'error': 'El carrito está vacío.'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            for item in carrito_items:
                item.estado_pago = 'approved' 
                item.id_metodoPago = metodo_pago 
                item.fecha_compra = timezone.now() 
                item.save()

        return Response({'message': 'Compra realizada con éxito.'}, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error en el checkout: {e}", exc_info=True)
        return Response({'error': 'Error interno del servidor durante el checkout: ' + str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ---
## Login/Registro/RefreshToken (Login y Registro Públicos, Refresh Protegido)
# ---
class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny] 

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })

@api_view(['POST'])
@permission_classes([AllowAny]) 
def token_refresh(request):
    serializer = TokenRefreshView().get_serializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response(serializer.validated_data, status=status.HTTP_200_OK)


# ---
## Perfiles de Usuario (Protegido)
# ---
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def profile_api_view(request):
    if request.method == 'GET':
        profiles = Profile.objects.all()
        profiles_serializer = ProfileSerializer(profiles, many=True)
        return Response(profiles_serializer.data, status=status.HTTP_200_OK)
    elif request.method == 'POST':
        profile_serializer = ProfileSerializer(data=request.data)
        if profile_serializer.is_valid():
            if 'user' not in profile_serializer.validated_data:
                profile_serializer.save(user=request.user)
            else:
                profile_serializer.save()
            return Response(profile_serializer.data, status=status.HTTP_201_CREATED)
        return Response(profile_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def obtener_usuario_autenticado(request):
    try:
        profile = Profile.objects.get(user=request.user)
        profile_serializer = ProfileSerializer(profile)
        return Response(profile_serializer.data, status=status.HTTP_200_OK)
    except Profile.DoesNotExist:
        return Response({'error': 'Perfil no encontrado'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def profile_detail_api_view(request, pk=None):
    profile = Profile.objects.filter(user=request.user, id=pk).first() 
    if not profile and request.user.is_staff: 
        profile = Profile.objects.filter(id=pk).first()

    if profile:
        if request.method == 'GET':
            profile_serializer = ProfileSerializer(profile)
            return Response(profile_serializer.data, status=status.HTTP_200_OK)
        elif request.method == 'PUT':
            profile_serializer = ProfileSerializer(profile, data=request.data)
            if profile_serializer.is_valid():
                profile_serializer.save()
                return Response(profile_serializer.data, status=status.HTTP_200_OK)
            return Response(profile_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        elif request.method == 'DELETE':
            if profile.user != request.user and not request.user.is_staff:
                return Response({'message': 'No tienes permiso para eliminar este perfil'}, status=status.HTTP_403_FORBIDDEN)
            profile.delete()
            return Response({'message': 'Perfil eliminado correctamente'}, status=status.HTTP_200_OK)
    return Response({'message': 'No se ha encontrado un perfil con estos datos o no tienes permiso para acceder a él'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def actualizar_perfil_parcial(request):
    try:
        profile = Profile.objects.get(user=request.user)
        # CORRECCIÓN: Añade 'image' a los campos permitidos
        campos_permitidos = {'telephone', 'dni', 'address', 'image'} 
        data = {k: v for k, v in request.data.items() if k in campos_permitidos}

        if not data:
            return Response(
                {'error': 'No se proporcionaron campos válidos para actualizar. Campos permitidos: telephone, dni, address, image'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = ProfileSerializer(profile, data=data, partial=True, context={'request': request}) # Pasa el request
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Profile.DoesNotExist:
        return Response({'error': 'Perfil no encontrado.'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error al actualizar perfil: {str(e)}", exc_info=True)
        return Response(
            {'error': 'Ocurrió un error al actualizar el perfil'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny] 

    def post(self, request, *args, **kwargs):
        try:
            register_serializer = self.get_serializer(data=request.data)
            register_serializer.is_valid(raise_exception=True)
            user = register_serializer.save()

            login_data = {
                'email': request.data['email'],
                'password': request.data['password']
            }
            login_serializer = LoginSerializer(data=login_data)
            login_serializer.is_valid(raise_exception=True)
            user = login_serializer.validated_data['user']

            refresh = RefreshToken.for_user(user)

            profile = Profile.objects.get(user=user)

            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': ProfileSerializer(profile, context={'request': request}).data # Pasa el request aquí también
            }, status=status.HTTP_201_CREATED)

        except serializers.ValidationError as e:
            return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error during registration: {e}", exc_info=True)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny] 

    def post(self, request, *args, **kwargs):
        try:
            register_serializer = self.get_serializer(data=request.data)
            register_serializer.is_valid(raise_exception=True)
            user = register_serializer.save()

            login_data = {
                'email': request.data['email'],
                'password': request.data['password']
            }
            login_serializer = LoginSerializer(data=login_data)
            login_serializer.is_valid(raise_exception=True)
            user = login_serializer.validated_data['user']

            refresh = RefreshToken.for_user(user)

            profile = Profile.objects.get(user=user)

            return Response({
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': ProfileSerializer(profile).data
            }, status=status.HTTP_201_CREATED)

        except serializers.ValidationError as e:
            return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error during registration: {e}", exc_info=True)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
# ---
## Integración con Mercado Pago (Públicas o con seguridad de webhook)
# ---
@csrf_exempt
@api_view(['POST']) 
@permission_classes([AllowAny]) 
def create_preference(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            cart_items_payload = data.get('items', [])
            user_id = data.get('user_id')

            logger.info(f"create_preference: Datos recibidos: {data}")
            logger.info(f"create_preference: Ítems recibidos: {cart_items_payload}")

            if not cart_items_payload:
                logger.error("create_preference: No items in cart payload.")
                return JsonResponse({'error': 'No items in cart'}, status=400)

            try:
                user = User.objects.get(pk=user_id)
            except User.DoesNotExist:
                logger.error(f"create_preference: User with ID {user_id} not found.")
                return JsonResponse({'error': 'User not found'}, status=404)

            items_mp = []
            external_reference = f"order-{user.id}-{uuid.uuid4()}" 
            
            payer_email = user.email if user.email else "test_user@example.com" 

            with transaction.atomic():
                for item_payload in cart_items_payload:
                    destino_id = item_payload.get('id_destino')
                    
                    cantidad_comprada_str = item_payload.get('quantity')
                    cantidad_comprada = None 

                    if cantidad_comprada_str:
                        try:
                            cantidad_comprada = int(cantidad_comprada_str)
                        except ValueError:
                            logger.warning(f"Invalid quantity value '{cantidad_comprada_str}' for item {item_payload}. It must be an integer. Skipping item.")
                            continue 
                    
                    if not destino_id or cantidad_comprada is None or cantidad_comprada <= 0:
                        logger.warning(f"Invalid or incomplete item in payload, will be ignored: {item_payload}. Missing id_destino or quantity (or quantity is not a valid positive integer).")
                        continue 

                    try:
                        destino = Destinos.objects.get(pk=destino_id)
                    except Destinos.DoesNotExist:
                        logger.warning(f"Destination with ID {destino_id} not found in DB for item_payload: {item_payload}. Skipping item.")
                        continue 

                    try:
                        carrito_item_db = Carrito.objects.get(
                            user=user,
                            id_destino=destino, 
                            estado_pago='cart_active' 
                        )
                        
                        carrito_item_db.cantidad = cantidad_comprada
                        carrito_item_db.estado_pago = 'in_process' 
                        carrito_item_db.mercadopago_external_reference = external_reference
                        carrito_item_db.save()
                        logger.info(f"Cart ID {carrito_item_db.id_compra} for destination {destino_id} updated to 'in_process'.")

                        items_mp.append({
                            "id": str(destino.pk), 
                            "title": item_payload.get('nombre_Destino', destino.nombre_Destino),
                            "description": item_payload.get('description', destino.descripcion), 
                            "quantity": cantidad_comprada,
                            "currency_id": "ARS",
                            "unit_price": float(item_payload.get('unit_price', destino.precio_Destino)), 
                            "picture_url": item_payload.get('image', '') 
                        })
                    except Carrito.DoesNotExist:
                        logger.warning(f"Cart item for user {user_id} and destination {destino_id} not found in 'cart_active' state. Skipping item.")
                        continue 
                    except Exception as e: 
                        logger.error(f"Unexpected error processing cart item for destination {destino_id} (user {user_id}): {e}", exc_info=True)
                        continue

                if not items_mp:
                    logger.warning("create_preference: After processing all payload items, 'items_mp' is empty. No valid items for Mercado Pago.")
                    return JsonResponse({'error': 'No valid items to process for payment.'}, status=400)

                success_url = f"{settings.FRONTEND_BASE_URL}/payment-success/" 
                failure_url = f"{settings.FRONTEND_BASE_URL}/payment-failure/"
                pending_url = f"{settings.FRONTEND_BASE_URL}/payment-pending/"
                notification_url = f"{settings.BACKEND_BASE_URL}/api/mercadopago/notifications/"

                logger.info(f"DEBUG_URLS: Success URL: {success_url}")
                logger.info(f"DEBUG_URLS: Failure URL: {failure_url}")
                logger.info(f"DEBUG_URLS: Pending URL: {pending_url}")
                logger.info(f"DEBUG_URLS: Notification URL: {notification_url}")

                preference_data = {
                    "items": items_mp,
                    "payer": {
                        "email": payer_email,
                    },
                    "back_urls": {
                        "success": success_url, 
                        "failure": failure_url,
                        "pending": pending_url
                    },
                    "auto_return": "approved", 
                    "notification_url": notification_url,
                    "external_reference": external_reference, 
                    "binary_mode": False, 
                    "metadata": { 
                        "user_id": user.id,
                    }
                }

                logger.info(f"create_preference: Sending preference to Mercado Pago: {json.dumps(preference_data, indent=2)}") 

                preference_response = sdk.preference().create(preference_data) 
                
                mp_status = preference_response.get("status")
                mp_response = preference_response.get("response")

                if mp_status in [200, 201] and mp_response:
                    preference = mp_response
                    logger.info(f"Mercado Pago preference created successfully. ID: {preference['id']}")

                    Carrito.objects.filter(mercadopago_external_reference=external_reference, user=user)\
                        .update(mercadopago_preference_id=preference['id'])

                    return JsonResponse({
                        'init_point': preference['init_point'],
                        'preference_id': preference['id'],
                        'external_reference': external_reference 
                    })
                else:
                    full_mp_error_details = preference_response
                    logger.error(f"Error creating Mercado Pago preference. Full MP details: {full_mp_error_details}")
                    
                    Carrito.objects.filter(mercadopago_external_reference=external_reference, user=user)\
                        .update(estado_pago='cart_active', mercadopago_external_reference=None, mercadopago_preference_id=None)
                    
                    return JsonResponse({
                        'error': 'Error creating preference in Mercado Pago',
                        'mercadopago_details': full_mp_error_details
                    }, status=400)

        except json.JSONDecodeError:
            logger.error("create_preference: Invalid JSON received.", exc_info=True)
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.error(f"Unexpected error in create_preference: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'Internal server error: ' + str(e)}, status=500)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
@api_view(['GET', 'POST']) 
@permission_classes([AllowAny]) 
def mercadopago_notifications(request):
    """
    Esta vista maneja las notificaciones (webhooks) de Mercado Pago.
    Cuando un pago cambia de estado, Mercado Pago envía una notificación aquí.
    """
    if request.method == 'GET':
        return JsonResponse({'status': 'ok'})
    elif request.method == 'POST':
        try:
            notification_data = json.loads(request.body)
            topic = notification_data.get('topic')
            resource_id = notification_data.get('id') 
            
            logger.info(f"Notificación de Mercado Pago recibida: Topic={topic}, Resource ID={resource_id}")

            if topic == 'payment':
                payment_info_response = sdk.payment().get(resource_id)
                if payment_info_response["status"] != 200:
                    logger.error(f"Error al obtener detalles del pago {resource_id} desde MP: {payment_info_response.get('message')}")
                    return JsonResponse({'error': 'Error fetching payment details from MP'}, status=200) 

                payment_data = payment_info_response['response']
                payment_status = payment_data['status'] 
                payment_id = payment_data['id']
                external_reference = payment_data.get('external_reference')
                logger.info(f"Payment {payment_id} status: {payment_status}, External Ref: {external_reference}")

                with transaction.atomic():
                    # Buscar ítems del carrito asociados a esta external_reference y al usuario del pago
                    # Asumiendo que `metadata` en la preferencia de MP contiene `user_id` del comprador
                    user_id = payment_data.get('metadata', {}).get('user_id')
                    
                    if user_id:
                        user = User.objects.get(pk=user_id)
                        # Busca los ítems que se pusieron 'in_process' con esta external_reference
                        # y que pertenecen a este usuario
                        cart_items = Carrito.objects.filter(
                            mercadopago_external_reference=external_reference,
                            user=user,
                            estado_pago='in_process' # Solo ítems que estaban esperando confirmación
                        )

                        if payment_status == 'approved':
                            logger.info(f"Payment {payment_id} approved. Updating {cart_items.count()} cart items to 'approved'.")
                            for item in cart_items:
                                item.estado_pago = 'approved'
                                item.fecha_compra = timezone.now()
                                item.mercadopago_payment_id = payment_id # Guardar el ID de pago de MP
                                item.save()
                                # Opcional: Reducir el stock del destino aquí o en una señal
                                # item.id_destino.cantidad_Disponible -= item.cantidad
                                # item.id_destino.save()
                        elif payment_status == 'pending':
                            logger.info(f"Payment {payment_id} pending. Items remain 'in_process'.")
                            # No se requiere acción si ya están en 'in_process'
                        else: # rejected, cancelled, refunded, etc.
                            logger.info(f"Payment {payment_id} {payment_status}. Reverting {cart_items.count()} items to 'cart_active'.")
                            for item in cart_items:
                                item.estado_pago = 'cart_active' # Vuelve a estar en el carrito activo
                                item.mercadopago_external_reference = None
                                item.mercadopago_preference_id = None
                                item.mercadopago_payment_id = None
                                item.save()
                    else:
                        logger.warning(f"Notification received for payment {payment_id} but no user_id found in metadata. Cannot update cart items.")
            
            return JsonResponse({'status': 'notification processed'}, status=200)

        except json.JSONDecodeError:
            logger.error("mercadopago_notifications: Invalid JSON received.", exc_info=True)
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.error(f"Unexpected error in mercadopago_notifications: {str(e)}", exc_info=True)
            return JsonResponse({'error': 'Internal server error: ' + str(e)}, status=500)
    return JsonResponse({'error': 'Method not allowed'}, status=405)

# Vistas de éxito/fracaso/pendiente para Mercado Pago (simplemente devuelven un mensaje)
@api_view(['GET'])
@permission_classes([AllowAny]) # Estas vistas deben ser públicas para el auto_return de MP
def mercadopago_success(request):
    return JsonResponse({'message': 'Pago exitoso. Gracias por tu compra!'}, status=200)

@api_view(['GET'])
@permission_classes([AllowAny])
def mercadopago_failure(request):
    return JsonResponse({'message': 'Pago fallido. Por favor, intenta de nuevo.'}, status=400)

@api_view(['GET'])
@permission_classes([AllowAny])
def mercadopago_pending(request):
    return JsonResponse({'message': 'Pago pendiente de aprobación. Recibirás una notificación cuando sea procesado.'}, status=200)

class ChangePasswordView(generics.UpdateAPIView): 
    serializer_class = ChangePasswordSerializer
    model = User 
    permission_classes = (IsAuthenticated,)
    http_method_names = ['post', 'put', 'patch'] 

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def post(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        logger.debug(f"ChangePasswordView: User object retrieved for password change: ID={self.object.pk}, Email={self.object.email}")

        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            new_password = serializer.validated_data.get("new_password")
            logger.debug(f"ChangePasswordView: Serializer is valid. New password length: {len(new_password)}")

            # Log password hash BEFORE setting new password (should be old hash)
            old_hash = self.object.password
            logger.debug(f"ChangePasswordView: User password hash BEFORE set_password: {old_hash[:10]}...") # Log first 10 chars for security

            self.object.set_password(new_password)
            
            # Log password hash AFTER setting new password but BEFORE saving
            new_hash_before_save = self.object.password
            logger.debug(f"ChangePasswordView: User password hash AFTER set_password (before save): {new_hash_before_save[:10]}...")

            self.object.save()
            
            # Log password hash AFTER saving
            new_hash_after_save = self.object.password
            logger.debug(f"ChangePasswordView: User password hash AFTER save: {new_hash_after_save[:10]}...")

            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Contraseña actualizada exitosamente',
                'data': []
            }
            return Response(response)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)