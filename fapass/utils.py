import os
import secrets
import string
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings


def generate_salt():
    """Genera un salt único para el cifrado"""
    return os.urandom(16).hex()


def get_master_key():
    """Obtiene la clave maestra desde settings o genera una por defecto"""
    # En producción, esto debe venir de una variable de entorno
    master_key = getattr(settings, 'FAPASS_MASTER_KEY', 'default-master-key-change-in-production')
    return master_key.encode()


def derive_key(password_salt):
    """Deriva una clave de cifrado usando PBKDF2"""
    salt = bytes.fromhex(password_salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(get_master_key()))
    return key


def encrypt_password(password):
    """
    Cifra una contraseña usando AES-256 con salt único
    Retorna: (encrypted_password, salt)
    """
    # Generar salt único
    salt = generate_salt()
    
    # Derivar clave de cifrado
    key = derive_key(salt)
    
    # Crear cipher
    cipher = Fernet(key)
    
    # Cifrar contraseña
    encrypted_password = cipher.encrypt(password.encode()).decode()
    
    return encrypted_password, salt


def decrypt_password(encrypted_password, password_salt):
    """
    Descifra una contraseña usando el salt proporcionado
    Retorna: password (string)
    """
    # Derivar clave de cifrado
    key = derive_key(password_salt)
    
    # Crear cipher
    cipher = Fernet(key)
    
    # Descifrar contraseña
    decrypted_password = cipher.decrypt(encrypted_password.encode()).decode()
    
    return decrypted_password


def generate_secure_password(
    length=16,
    include_uppercase=True,
    include_lowercase=True,
    include_numbers=True,
    include_symbols=True,
    exclude_ambiguous=True
):
    """
    Genera una contraseña segura con los parámetros especificados
    """
    if length < 4:
        raise ValueError("La longitud mínima debe ser 4 caracteres")
    
    # Definir conjuntos de caracteres
    uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    lowercase = 'abcdefghijklmnopqrstuvwxyz'
    numbers = '0123456789'
    symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    
    # Caracteres ambiguos a excluir
    ambiguous = '0Ol1Il|`'
    
    # Construir el conjunto de caracteres disponibles
    available_chars = ''
    required_chars = []
    
    if include_uppercase:
        chars = uppercase
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        available_chars += chars
        if chars:
            required_chars.append(secrets.choice(chars))
    
    if include_lowercase:
        chars = lowercase
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        available_chars += chars
        if chars:
            required_chars.append(secrets.choice(chars))
    
    if include_numbers:
        chars = numbers
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        available_chars += chars
        if chars:
            required_chars.append(secrets.choice(chars))
    
    if include_symbols:
        chars = symbols
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in ambiguous)
        available_chars += chars
        if chars:
            required_chars.append(secrets.choice(chars))
    
    if not available_chars:
        raise ValueError("Debe seleccionar al menos un tipo de carácter")
    
    # Generar contraseña
    password_chars = required_chars[:]
    
    # Completar hasta la longitud requerida
    remaining_length = length - len(required_chars)
    for _ in range(remaining_length):
        password_chars.append(secrets.choice(available_chars))
    
    # Mezclar los caracteres
    secrets.SystemRandom().shuffle(password_chars)
    
    return ''.join(password_chars)


def validate_password_strength(password):
    """
    Valida la fortaleza de una contraseña
    Retorna: (es_fuerte: bool, puntuacion: int, sugerencias: list)
    """
    score = 0
    suggestions = []
    
    # Longitud
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use al menos 8 caracteres (recomendado 12+)")
    
    # Mayúsculas
    if any(c.isupper() for c in password):
        score += 1
    else:
        suggestions.append("Incluya al menos una letra mayúscula")
    
    # Minúsculas
    if any(c.islower() for c in password):
        score += 1
    else:
        suggestions.append("Incluya al menos una letra minúscula")
    
    # Números
    if any(c.isdigit() for c in password):
        score += 1
    else:
        suggestions.append("Incluya al menos un número")
    
    # Símbolos
    symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    if any(c in symbols for c in password):
        score += 1
    else:
        suggestions.append("Incluya al menos un símbolo especial")
    
    # Caracteres únicos
    unique_chars = len(set(password))
    if unique_chars >= len(password) * 0.8:
        score += 1
    else:
        suggestions.append("Evite repetir muchos caracteres")
    
    # Patrones comunes
    common_patterns = ['123', 'abc', 'qwerty', 'password', 'admin']
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 2
        suggestions.append("Evite patrones comunes como '123', 'abc', 'qwerty'")
    
    # Determinar si es fuerte
    is_strong = score >= 5 and len(password) >= 8
    
    return is_strong, max(0, score), suggestions


def generate_token():
    """Genera un token seguro para acceso"""
    return secrets.token_urlsafe(32)


def validate_url_domain(url, allowed_domains):
    """
    Valida si una URL pertenece a los dominios permitidos
    """
    from urllib.parse import urlparse
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remover www. si existe
        if domain.startswith('www.'):
            domain = domain[4:]
        
        for allowed_domain in allowed_domains:
            if allowed_domain.lower() in domain or domain in allowed_domain.lower():
                return True
        
        return False
    except:
        return False


def extract_domain(url):
    """Extrae el dominio de una URL"""
    from urllib.parse import urlparse
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remover www. si existe
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain
    except:
        return None


def sanitize_selector(css_selector):
    """
    Sanitiza un selector CSS para evitar inyección de código
    """
    if not css_selector:
        return ''
    
    # Remover caracteres peligrosos
    dangerous_chars = ['<', '>', '"', "'", ';', '(', ')', '{', '}']
    sanitized = css_selector
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    # Validar que sea un selector CSS válido básico
    import re
    if not re.match(r'^[a-zA-Z0-9\[\]="\'#\.\-_\s:,\*\+~>]+$', sanitized):
        return 'input[type="text"], input[type="email"]'  # Selector por defecto seguro
    
    return sanitized.strip()


def rate_limit_key(request, prefix='fapass'):
    """
    Genera una clave única para rate limiting basada en IP y usuario
    """
    ip = request.META.get('REMOTE_ADDR', 'unknown')
    user_id = request.user.id if request.user.is_authenticated else 'anonymous'
    return f"{prefix}:{ip}:{user_id}"


def is_suspicious_activity(request, token):
    """
    Detecta actividad sospechosa en el uso de tokens
    """
    from .models import AccessLog
    from django.utils import timezone
    from datetime import timedelta
    
    # Verificar múltiples intentos desde la misma IP en poco tiempo
    recent_attempts = AccessLog.objects.filter(
        token=token,
        ip_address=request.META.get('REMOTE_ADDR'),
        timestamp__gte=timezone.now() - timedelta(minutes=5)
    ).count()
    
    if recent_attempts > 10:  # Más de 10 intentos en 5 minutos
        return True, "Demasiados intentos desde la misma IP"
    
    # Verificar intentos fallidos consecutivos
    recent_failures = AccessLog.objects.filter(
        token=token,
        success=False,
        timestamp__gte=timezone.now() - timedelta(minutes=15)
    ).count()
    
    if recent_failures > 5:  # Más de 5 fallos en 15 minutos
        return True, "Demasiados intentos fallidos"
    
    return False, None


def clean_old_logs(days_to_keep=90):
    """
    Limpia logs antiguos para mantener la base de datos optimizada
    """
    from .models import AccessLog
    from django.utils import timezone
    from datetime import timedelta
    
    cutoff_date = timezone.now() - timedelta(days=days_to_keep)
    deleted_count = AccessLog.objects.filter(timestamp__lt=cutoff_date).delete()[0]
    
    return deleted_count


def export_user_data(user):
    """
    Exporta todos los datos de un usuario para GDPR/transparencia
    """
    from .models import AuthorizedSite, StoredCredential, AccessToken, AccessLog
    
    data = {
        'sites': [],
        'credentials': [],
        'tokens': [],
        'access_logs': []
    }
    
    # Sitios autorizados
    for site in AuthorizedSite.objects.filter(owner=user):
        data['sites'].append({
            'name': site.name,
            'url': site.url,
            'login_url': site.login_url,
            'created_at': site.created_at.isoformat(),
            'is_active': site.is_active
        })
    
    # Credenciales (sin contraseñas)
    for credential in StoredCredential.objects.filter(owner=user):
        data['credentials'].append({
            'site_name': credential.site.name,
            'username': credential.username,
            'description': credential.description,
            'created_at': credential.created_at.isoformat(),
            'last_used': credential.last_used.isoformat() if credential.last_used else None,
            'is_active': credential.is_active
        })
    
    # Tokens
    for token in AccessToken.objects.filter(owner=user):
        data['tokens'].append({
            'credential_site': token.credential.site.name,
            'credential_username': token.credential.username,
            'collaborator_email': token.collaborator_email,
            'collaborator_name': token.collaborator_name,
            'created_at': token.created_at.isoformat(),
            'expires_at': token.expires_at.isoformat(),
            'max_uses': token.max_uses,
            'current_uses': token.current_uses,
            'is_active': token.is_active
        })
    
    # Logs de acceso
    for log in AccessLog.objects.filter(token__owner=user):
        data['access_logs'].append({
            'site_url': log.site_url,
            'action': log.action,
            'timestamp': log.timestamp.isoformat(),
            'success': log.success,
            'ip_address': log.ip_address
        })
    
    return data