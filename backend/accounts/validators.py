from django.core.exceptions import ValidationError
from django.utils import timezone

def validate_fecha_futura(value):
    if value < timezone.now():
        raise ValidationError("La fecha de salida no puede ser anterior a la fecha actual.")