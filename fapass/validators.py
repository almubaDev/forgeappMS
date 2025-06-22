from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
import re


def validate_css_selector(value):
    """
    Valida que el valor sea un selector CSS seguro
    """
    if not value:
        return
    
    # Caracteres peligrosos
    dangerous_patterns = [
        r'<script',
        r'javascript:',
        r'on\w+\s*=',
        r'expression\s*\(',
        r'@import',
        r'url\s*\(',
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            raise ValidationError(
                'El selector CSS contiene contenido no permitido'
            )
    
    # Validar formato básico de selector CSS
    if not re.match(r'^[a-zA-Z0-9\[\]="\'#\.\-_\s:,\*\+~>]+$', value):
        raise ValidationError(
            'El selector CSS contiene caracteres no válidos'
        )


def validate_secure_url(value):
    """
    Valida que la URL sea segura (HTTPS)
    """
    url_validator = URLValidator()
    url_validator(value)
    
    if not value.startswith('https://'):
        raise ValidationError(
            'Solo se permiten URLs HTTPS por seguridad'
        )


def validate_token_duration(value):
    """
    Valida que la duración del token esté en un rango aceptable
    """
    if value < 1:
        raise ValidationError(
            'La duración mínima es 1 hora'
        )
    
    if value > 720:  # 30 días
        raise ValidationError(
            'La duración máxima es 720 horas (30 días)'
        )


def validate_password_strength(value):
    """
    Valida que la contraseña tenga suficiente fortaleza
    """
    if len(value) < 8:
        raise ValidationError(
            'La contraseña debe tener al menos 8 caracteres'
        )
    
    # Al menos una mayúscula
    if not re.search(r'[A-Z]', value):
        raise ValidationError(
            'La contraseña debe contener al menos una letra mayúscula'
        )
    
    # Al menos una minúscula
    if not re.search(r'[a-z]', value):
        raise ValidationError(
            'La contraseña debe contener al menos una letra minúscula'
        )
    
    # Al menos un número
    if not re.search(r'\d', value):
        raise ValidationError(
            'La contraseña debe contener al menos un número'
        )


def validate_collaborator_email(value):
    """
    Valida el formato del email del colaborador
    """
    from django.core.validators import EmailValidator
    
    email_validator = EmailValidator()
    email_validator(value)
    
    # Evitar dominios temporales conocidos
    temp_domains = [
        '10minutemail.com',
        'guerrillamail.com',
        'mailinator.com',
        'tempmail.org'
    ]
    
    domain = value.split('@')[1].lower()
    if domain in temp_domains:
        raise ValidationError(
            'No se permiten emails de dominios temporales'
        )