# accounts/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny 

from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.conf import settings 
import logging

# Configura el logger
logger = logging.getLogger(__name__)

class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email es requerido'}, status=status.HTTP_400_BAD_REQUEST)

        # --- CAMBIO CLAVE AQUÍ: Usar filter().first() en lugar de get() ---
        user = User.objects.filter(email=email).first() 

        if not user:
            # Por seguridad, no revelamos si el email existe o no.
            # Siempre respondemos como si el correo hubiera sido enviado para evitar enumeración de usuarios.
            logger.info(f"Intento de recuperación de contraseña para email no registrado: {email}")
            return Response({'message': 'Si tu correo está registrado, recibirás un enlace para restablecer tu contraseña.'}, status=status.HTTP_200_OK)
        # --- FIN DEL CAMBIO CLAVE ---

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        frontend_base_url = "http://localhost:4200" # Asegúrate de que esta URL sea correcta para tu frontend
        reset_url = f"{frontend_base_url}/new-password/{uid}/{token}"

        try:
            send_mail(
                subject="Restablece tu contraseña",
                message=f"Hacé clic en el siguiente link para restablecer tu contraseña: {reset_url}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False, 
            )
            logger.info(f"Correo de recuperación enviado a {email}")
            return Response({'message': 'Se envió el correo de recuperación'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error al enviar correo de recuperación a {email}: {e}")
            return Response({'error': 'Error al enviar el correo de recuperación. Verifica la configuración de correo del servidor.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny] 

    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError):
            logger.warning(f"Intento de confirmación de recuperación de contraseña con token/UID inválido: UID={uidb64}, Token={token}")
            return Response({'error': 'Token inválido'}, status=status.HTTP_400_BAD_REQUEST)

        if not default_token_generator.check_token(user, token):
            logger.warning(f"Intento de confirmación de recuperación de contraseña con token inválido o expirado para usuario {user.email}")
            return Response({'error': 'Token inválido o expirado'}, status=status.HTTP_400_BAD_REQUEST)

        new_password = request.data.get('new_password')
        if not new_password:
            return Response({'error': 'La nueva contraseña es requerida'}, status=status.HTTP_400_BAD_REQUEST)

        # Opcional: Validar la fortaleza de la nueva contraseña aquí si aún no lo haces.
        # from django.contrib.auth.password_validation import validate_password, ValidationError
        # try:
        #     validate_password(new_password, user)
        # except ValidationError as e:
        #     logger.error(f"Error de validación de contraseña para usuario {user.email}: {e.messages}")
        #     return Response({'error': list(e.messages)}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        logger.info(f"Contraseña actualizada correctamente para usuario {user.email}")
        return Response({'message': 'Contraseña actualizada correctamente'}, status=status.HTTP_200_OK)