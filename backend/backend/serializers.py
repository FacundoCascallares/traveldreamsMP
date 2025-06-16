# accounts/serializers.py

from rest_framework import serializers
from accounts.models import Destinos, MetodoPago, Nosotros, Carrito, Profile
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password # Importar para validación de contraseña
from django.core.exceptions import ValidationError as DjangoValidationError # Importar para capturar errores de validación de Django
import logging # Para logging, si es necesario

# Inicialización del logger al principio del archivo
logger = logging.getLogger(__name__)

class DestinosSerializer(serializers.ModelSerializer):
    class Meta:
        model = Destinos
        fields = '__all__'

class MetodoPagoSerializer(serializers.ModelSerializer):
    class Meta:
        model = MetodoPago
        fields = '__all__'

class CarritoSerializer(serializers.ModelSerializer):
    # 'id_usuario' en el serializador se mapea al campo 'user' del modelo Carrito
    id_usuario = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        source='user' # Mapea 'id_usuario' a la relación 'user' en el modelo Carrito
    )

    # 'id_destino' en el serializador se mapea al campo 'id_destino' del modelo Carrito.
    id_destino = serializers.PrimaryKeyRelatedField(
        queryset=Destinos.objects.all(),
        # No es necesario 'source' si el nombre del campo es el mismo en el modelo
    )

    # 'id_metodoPago' en el serializador se mapea al campo 'id_metodoPago' del modelo Carrito.
    id_metodoPago = serializers.PrimaryKeyRelatedField(
        queryset=MetodoPago.objects.all(),
        # No es necesario 'source' si el nombre del campo es el mismo en el modelo
    )

    # Campo de solo lectura para incluir el nombre del destino
    # ¡Importante! Coincide con nombre_Destino de tu interfaz de Angular
    nombre_Destino = serializers.CharField(read_only=True, source='id_destino.nombre_Destino')
    
    # Campo de solo lectura para incluir la descripción del destino (útil para Mercado Pago)
    descripcion = serializers.CharField(read_only=True, source='id_destino.descripcion')

    # Campo para la URL de la imagen del destino.
    # Se usa SerializerMethodField porque el campo 'image' en Destinos es un CharField o URLField
    # que ya almacena la URL como string.
    image = serializers.SerializerMethodField()
    
    # Campo 'total' también de solo lectura, ya que se calcula en el modelo como una propiedad.
    total = serializers.DecimalField(max_digits=12, decimal_places=2, read_only=True)

    class Meta:
        model = Carrito
        fields = '__all__' # Usar '__all__' o especificar los campos, como ya lo tienes.
        extra_kwargs = {
            'fecha_creacion': {'read_only': True},
            # 'id_compra': {'read_only': True}, # Generalmente la PK es de solo lectura en la creación
        }
    
    # Método para obtener la URL completa de la imagen del destino.
    def get_image(self, obj):
        if obj.id_destino and obj.id_destino.image:
            request = self.context.get('request')
            if request:
                # Si la imagen ya es una URL absoluta (ej. empieza con 'http'), la devolvemos directamente.
                if obj.id_destino.image.startswith('http'):
                    return obj.id_destino.image
                else:
                    # Si es una ruta relativa (ej. '/media/destinos/imagen.jpg'), construimos la URL absoluta.
                    return request.build_absolute_uri(obj.id_destino.image)
            # Si no hay contexto de request, devolvemos la ruta relativa.
            return obj.id_destino.image
        return None # Devuelve None si no hay imagen o destino asociado

    # --- VALIDACIÓN DE LA CANTIDAD ---
    def validate_cantidad(self, value):
        logger.debug(f"Validando cantidad. Valor recibido: {value}")
        
        if value <= 0:
            raise serializers.ValidationError({"cantidad": "La cantidad debe ser un número positivo."})

        destino = None
        stock_disponible_para_validacion = 0

        # Si es una actualización de un ítem existente (self.instance no es None)
        if self.instance: 
            destino = self.instance.id_destino
            logger.debug(f"Actualización: Cantidad actual del ítem en carrito: {self.instance.cantidad}")
            logger.debug(f"Actualización: Cantidad disponible inicial del destino: {destino.cantidad_Disponible}")
            # Sumamos la cantidad actual del ítem a la cantidad disponible del destino.
            # Esto 'libera' temporalmente la cantidad que este ítem ya ocupa para la validación.
            stock_disponible_para_validacion = destino.cantidad_Disponible + self.instance.cantidad
            logger.debug(f"Actualización: Stock efectivo disponible para validación: {stock_disponible_para_validacion}")
        else: # Si es una creación de un nuevo ítem en el carrito (self.instance es None)
            destino_id = self.initial_data.get('id_destino')
            if destino_id:
                try:
                    destino = Destinos.objects.get(pk=destino_id)
                    stock_disponible_para_validacion = destino.cantidad_Disponible
                    logger.debug(f"Creación: Cantidad disponible del destino: {destino.cantidad_Disponible}")
                    logger.debug(f"Creación: Stock efectivo disponible para validación: {stock_disponible_para_validacion}")
                except Destinos.DoesNotExist:
                    # Lanzar error con el formato de diccionario para que el frontend lo parseé correctamente
                    raise serializers.ValidationError({'id_destino': ["El destino especificado no existe."]})
            else:
                # Lanzar error con el formato de diccionario
                raise serializers.ValidationError({'id_destino': ["ID de destino es requerido para validar la cantidad en la creación."]})
        
        if destino is None:
            raise serializers.ValidationError({'general': ["No se pudo validar el stock: Destino no encontrado."]})

        # --- Lógica de Validación Final ---
        if value > stock_disponible_para_validacion:
            # Lanzar el error con un formato de diccionario para el campo 'cantidad'
            # para que el frontend pueda parsearlo correctamente.
            error_message = f"Solo quedan {destino.cantidad_Disponible} cupos disponibles para {destino.nombre_Destino}. " \
                            f"No puedes añadir más allá del stock total."
            logger.error(f"Falla de validación: Cantidad solicitada ({value}) excede el stock efectivo ({stock_disponible_para_validacion}) para {destino.nombre_Destino} (stock actual: {destino.cantidad_Disponible})")
            raise serializers.ValidationError({'cantidad': [error_message]})
        
        return value

class NosotrosSerializer(serializers.ModelSerializer):
    class Meta:
        model = Nosotros
        fields = '__all__'
        # Asegúrate de que id_nosotros sea de solo lectura si es auto-generado
        read_only_fields = ['id_nosotros'] 

class RegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True},
        }
    
    def validate(self, attrs):
        email = attrs.get('email')
        
        # Utiliza `username=email` ya que tu sistema de autenticación usa el email como username
        if User.objects.filter(username=email).exists(): 
            raise serializers.ValidationError({"email": "Este correo electrónico ya está registrado."})
            
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Las contraseñas no coinciden."})
        
        # Validar la fortaleza de la contraseña usando los validadores de Django
        try:
            validate_password(attrs['password'])
        except DjangoValidationError as e:
            raise serializers.ValidationError({"password": list(e.messages)})

        return attrs

    def create(self, validated_data):
        email = validated_data['email']
        
        # Ya validamos en `validate` que el email no exista, pero es buena práctica para la claridad
        if User.objects.filter(username=email).exists():
             raise serializers.ValidationError({"email": "Este correo electrónico ya está registrado."})
            
        validated_data.pop('password2')
        user = User(
            username=email, # Usamos el email como username para la autenticación
            email=email,
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        # --- AÑADIDOS PARA DEPURACIÓN ---
        logger.debug(f"LoginSerializer - Intentando autenticar: email='{email}'")
        # Por seguridad, no loguear la contraseña directamente, solo su existencia o longitud
        logger.debug(f"LoginSerializer - Contraseña recibida: {'Sí' if password else 'No'} (Longitud: {len(password) if password else 0})")
        # --- FIN DEPURACIÓN ---

        # Usamos el email como username para authenticate
        user = authenticate(request=self.context.get('request'), username=email, password=password)
        
        if not user:
            logger.warning(f"LoginSerializer - Fallo de autenticación para email: '{email}'. Usuario no encontrado o contraseña incorrecta.")
            raise serializers.ValidationError('Credenciales inválidas')
        
        if not user.is_active:
            logger.warning(f"LoginSerializer - Intento de login de cuenta inactiva para email: '{email}'.")
            raise serializers.ValidationError('Cuenta inactiva.')

        logger.debug(f"LoginSerializer - Autenticación exitosa para usuario: '{user.email}'")
        attrs['user'] = user
        return attrs
    
class ProfileSerializer(serializers.ModelSerializer):
    # Campos de User expuestos a través de Profile
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    first_name = serializers.CharField(source='user.first_name', required=False, allow_blank=True)
    last_name = serializers.CharField(source='user.last_name', required=False, allow_blank=True)

    class Meta:
        model = Profile
        # ¡CORRECCIÓN CLAVE AQUÍ!: Cambiar 'profile_picture' a 'image'
        fields = ('id', 'user', 'username', 'email', 'first_name', 'last_name', 'telephone', 'dni', 'address', 'image')
        read_only_fields = ('id', 'user', 'username', 'email') # Estos campos son de solo lectura

    def update(self, instance, validated_data):
        # Manejar la actualización de campos del modelo User
        user_data = {}
        if 'first_name' in validated_data:
            user_data['first_name'] = validated_data.pop('first_name')
        if 'last_name' in validated_data:
            user_data['last_name'] = validated_data.pop('last_name')

        # Actualizar campos del modelo Profile
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Actualizar campos del modelo User si se proporcionaron
        if user_data:
            user = instance.user
            for attr, value in user_data.items():
                setattr(user, attr, value)
            user.save()


# --- SERIALIZADOR PARA EL CAMBIO DE CONTRASEÑA ---
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True)
    confirm_new_password = serializers.CharField(required=True, write_only=True)

    def validate_old_password(self, value):
        # Accedemos al usuario a través del contexto de la solicitud
        user = self.context['request'].user
        # Verificamos si la contraseña antigua proporcionada coincide con la contraseña actual del usuario
        if not user.check_password(value):
            raise serializers.ValidationError("Contraseña antigua incorrecta.")
        return value

    def validate(self, data):
        new_password = data.get('new_password')
        confirm_new_password = data.get('confirm_new_password')

        # 1. Las nuevas contraseñas deben coincidir
        if new_password != confirm_new_password:
            raise serializers.ValidationError({"new_password": "Las nuevas contraseñas no coinciden.", "confirm_new_password": "Las nuevas contraseñas no coinciden."})
        
        # 2. La nueva contraseña no debe ser igual a la antigua
        user = self.context['request'].user
        if user.check_password(new_password):
            raise serializers.ValidationError({"new_password": "La nueva contraseña no puede ser igual a la anterior."})

        # 3. Validar la fortaleza de la nueva contraseña con los validadores de Django
        try:
            validate_password(new_password, user=user)
        except DjangoValidationError as e:
            # Captura los errores de validación de Django y los formatea para DRF
            raise serializers.ValidationError({"new_password": list(e.messages)})
        
        return data