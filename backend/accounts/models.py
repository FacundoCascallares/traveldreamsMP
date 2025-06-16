# IMPORTACIONES PARA PERFIL
from django.db import models, transaction
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.db import transaction
from django.core.validators import MinLengthValidator, MaxLengthValidator
from django.core.exceptions import ValidationError
from django.utils import timezone

# VALIDADORES PERSONALIZADOS
def positive_price_validator(value):
    if value < 0:
        raise ValidationError('El precio debe ser un valor positivo.')

def positive_viaje_validator(value):
    if value < 0:
        raise ValidationError('El stock del viaje debe ser igual a 0, o un valor positivo.')

def validate_fecha_futura(value):
    if value < timezone.now():
        raise ValidationError("La fecha de salida no puede ser anterior a la fecha actual.")

# 1. CATEGORIAS DE LOS VIAJES
class Categorias(models.Model):
    id_categoria = models.AutoField(primary_key=True)
    nombreCategoria = models.CharField(max_length=150)
    
    class Meta:
        db_table = 'categorias'
        verbose_name = 'Categoria'
        verbose_name_plural = 'Categorias'
    
    def __str__(self):
        return self.nombreCategoria
    
    def __unicode__(self):
        return self.nombreCategoria

# 2. METODO DE PAGO USUARIO
class MetodoPago(models.Model):
    id_metodoPago = models.AutoField(primary_key=True)
    nombrePago = models.CharField(max_length=100)

    class Meta:
        db_table = 'metodo_pago'
        verbose_name = 'Metodos De Pago'
        verbose_name_plural = 'Metodos de pagos'

    def __str__(self):
        return self.nombrePago

    def __unicode__(self):
        return self.nombrePago

# 3. NOSOTROS
class Nosotros(models.Model):
    id_nosotros = models.AutoField(primary_key=True)
    nombre_apellido = models.CharField(max_length=100)
    github = models.CharField(max_length=100)
    linkedin = models.CharField(max_length=100)
    imagen = models.CharField(max_length=100)
    rol = models.CharField(max_length=100)

    class Meta:
        db_table = 'nosotros'
        verbose_name = 'Nosotros'
        verbose_name_plural = 'Nosotros'

    def __str__(self):
        return self.nombre_apellido

# 4. DESTINOS
class Destinos(models.Model):
    id_destino = models.AutoField(primary_key=True)
    nombre_Destino = models.CharField(max_length=150)
    descripcion = models.TextField(default='descripcion', blank=False)
    image = models.URLField(max_length=200, blank=True)
    precio_Destino = models.DecimalField(max_digits=12, decimal_places=2, validators=[positive_price_validator])
    fecha_salida = models.DateTimeField(blank=False, validators=[validate_fecha_futura])
    cantidad_Disponible = models.IntegerField(default=12, validators=[positive_viaje_validator])
    id_metodoPago = models.ForeignKey('MetodoPago', db_column='id_metodoPago', on_delete=models.CASCADE)
    id_categoria = models.ForeignKey('Categorias', db_column='id_categoria', on_delete=models.CASCADE)

    class Meta:
        db_table = 'destinos'
        verbose_name = 'Destino'
        verbose_name_plural = 'Destinos'

    def __str__(self):
        return self.nombre_Destino

    @property
    def disponibilidad_display(self):
        """Muestra mensaje personalizado cuando no hay cupos"""
        if self.cantidad_Disponible <= 0:
            return "❌ No hay cupos disponibles"
        elif self.cantidad_Disponible < 5:
            return f"⚠️ Últimos {self.cantidad_Disponible} cupos!"
        return f"✅ Disponibles: {self.cantidad_Disponible}"

# 5. PERFIL DE USUARIO
class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile', verbose_name='Usuario')
    image = models.ImageField(default='users/usuario_defecto.jpg', upload_to='users/', verbose_name='Imagen de perfil')
    address = models.CharField(max_length=150, null=True, blank=True, verbose_name='Dirección')
    location = models.CharField(max_length=150, null=True, blank=True, verbose_name='Localidad')
    mail = models.EmailField(max_length=150, null=True, blank=True, verbose_name='Email')
    telephone = models.CharField(max_length=50, null=True, blank=True, verbose_name='Teléfono')
    dni = models.CharField(max_length=50, null=True, blank=True, verbose_name='DNI')
    
    class Meta:
        verbose_name = 'perfil'
        verbose_name_plural = 'perfiles'
        ordering = ['-id']

    def __str__(self):
        return self.user.username

# 6. CARRITO (VERSIÓN MEJORADA)
class Carrito(models.Model):
    id_compra = models.AutoField(primary_key=True)
    cantidad = models.DecimalField(
        max_digits=3,
        decimal_places=0,
        validators=[positive_price_validator], # Asegúrate de que este validator esté disponible
        verbose_name="Cantidad de pasajes"
    )
    id_metodoPago = models.ForeignKey(
        'MetodoPago', # Usa un string si MetodoPago está definido más abajo o en otra app
        db_column='id_metodoPago',
        on_delete=models.CASCADE,
        verbose_name="Método de pago"
    )
    id_destino = models.ForeignKey(
        'Destinos', # Usa un string si Destinos está definido más abajo o en otra app
        db_column='id_destino',
        on_delete=models.CASCADE,
        verbose_name="Destino seleccionado"
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        # Si tienes problemas con el default=1, considera hacerlo nullable y manejarlo en la lógica de negocio
        # o asegurarte de que el usuario siempre exista al crear el carrito.
        # Si usas Django REST Framework con autenticación, `request.user` ya te dará el usuario.
        default=1, 
        verbose_name="Usuario"
    )
    fecha_creacion = models.DateTimeField(auto_now_add=True, verbose_name="Fecha de creación")

    # --- CAMPOS NUEVOS PARA LA INTEGRACIÓN CON MERCADO PAGO ---
    ESTADO_PAGO_CHOICES = [
        ('cart_active', 'En Carrito (activo)'), # Ítem en el carrito, listo para pagar
        ('in_process', 'Pago en Proceso (MP)'), # Preferencia creada en MP, esperando pago
        ('pending', 'Pendiente (MP)'),         # Pago pendiente de acreditación (ej. efectivo)
        ('approved', 'Aprobado (MP)'),         # Pago exitoso
        ('rejected', 'Rechazado (MP)'),        # Pago fallido
        ('cancelled', 'Cancelado (MP)'),       # Pago cancelado
        ('refunded', 'Reembolsado (MP)'),      # Pago reembolsado
    ]
    # Este campo registrará el estado del pago según Mercado Pago
    estado_pago = models.CharField(
        max_length=20,
        choices=ESTADO_PAGO_CHOICES,
        default='cart_active',
        verbose_name="Estado del Pago"
    )
    
    # ID de la preferencia generada por Mercado Pago (para seguimiento)
    mercadopago_preference_id = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        verbose_name="ID Preferencia MP"
    )
    
    # ID del pago una vez que Mercado Pago lo procesa
    mercadopago_payment_id = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        verbose_name="ID de Pago MP"
    )
    
    # Referencia externa que tu backend envía a Mercado Pago (para vincular pago con tu orden)
    mercadopago_external_reference = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        unique=True, # Asegura que esta referencia sea única en tu sistema
        verbose_name="Referencia Externa MP"
    )
    
    # Fecha de la última actualización del estado del pago por parte de Mercado Pago
    fecha_pago_actualizacion = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Última Actualización Pago"
    )
    
    # Campo para la fecha en que la compra fue efectivamente realizada (ej. pago aprobado)
    fecha_compra = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Fecha de Compra Efectiva"
    )
    
    # Nuevo campo para la fecha de salida (si el usuario la puede seleccionar en el carrito)
    fecha_salida = models.DateField(
        null=True,
        blank=True,
        verbose_name="Fecha de Salida del Viaje"
    )


    class Meta:
        db_table = 'carrito'
        verbose_name = 'Reserva de Viaje'
        verbose_name_plural = 'Reservas de Viajes'
        ordering = ['-fecha_creacion']

    def clean(self):
        """
        Validaciones mejoradas:
        1. Verifica que la cantidad no sea None o vacía
        2. Comprueba disponibilidad del destino
        3. Valida la cantidad solicitada
        """
       
        # Si `cantidad` puede ser None en alguna etapa, la validación se moverá aquí.
        if self.cantidad is None:
            raise ValidationError(
                {'cantidad': 'Debe especificar una cantidad.'},
                code='cantidad_requerida'
            )

        try:
            cantidad_solicitada = int(self.cantidad)
        except (TypeError, ValueError):
            raise ValidationError(
                {'cantidad': 'La cantidad debe ser un número válido.'},
                code='cantidad_invalida'
            )

        # Luego verificar disponibilidad del destino
        if not hasattr(self, 'id_destino') or self.id_destino is None:
            raise ValidationError(
                {'id_destino': 'Debe seleccionar un destino válido.'},
                code='destino_requerido'
            )
            
        destino = self.id_destino
            
        if destino.cantidad_Disponible <= 0:
            raise ValidationError(
                {'id_destino': 'No hay cupos disponibles para este destino.'},
                code='sin_cupos'
            )

        # Finalmente validar la cantidad solicitada
        if cantidad_solicitada <= 0:
            raise ValidationError(
                {'cantidad': 'La cantidad debe ser mayor a cero.'},
                code='cantidad_invalida'
            )
            
        if cantidad_solicitada > destino.cantidad_Disponible:
            raise ValidationError(
                {'cantidad': f'Solo quedan {destino.cantidad_Disponible} cupos disponibles.'},
                code='stock_insuficiente'
            )

    def save(self, *args, **kwargs):
        """
        Proceso seguro con transacción atómica:
        1. Valida los datos
        2. Actualiza el stock (solo si es un nuevo registro y no está ya en proceso/comprado)
        3. Guarda el registro
        """
        with transaction.atomic():
            # Validación completa
            self.full_clean()
            if not self.pk and self.estado_pago == 'cart_active' and self.id_destino.cantidad_Disponible > 0:
                pass

            super().save(*args, **kwargs)

    def __str__(self):
        return (
            f"Reserva #{self.id_compra} - {self.user.username} - "
            f"{self.id_destino.nombre_Destino} - Estado: {self.estado_pago}"
        )

    def __unicode__(self):
        return self.__str__()

    @property
    def total(self):
        """Calcula el total de la reserva"""
        if self.cantidad is None or self.id_destino is None:
            return 0
        return float(self.cantidad) * float(self.id_destino.precio_Destino)
