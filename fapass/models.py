from django.db import models
from django.contrib.auth import get_user_model
from django.core.validators import URLValidator
from django.utils import timezone
import uuid
import secrets
import string
from datetime import timedelta

User = get_user_model()


class AuthorizedSite(models.Model):
    """
    Sitios web autorizados donde se pueden usar las credenciales
    """
    owner = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='authorized_sites',
        help_text="Usuario propietario de las credenciales"
    )
    name = models.CharField(
        max_length=100, 
        help_text="Nombre descriptivo del sitio (ej: Banco Estado)"
    )
    url = models.URLField(
        max_length=500, 
        help_text="URL principal del sitio (ej: https://www.bancoestado.cl)"
    )
    
    # Credenciales para este sitio
    username = models.CharField(
        max_length=255,
        help_text="Nombre de usuario o email para el login"
    )
    encrypted_password = models.TextField(
        help_text="Contraseña cifrada con AES-256"
    )
    password_salt = models.CharField(
        max_length=64,
        help_text="Salt único para el cifrado de esta contraseña"
    )
    
    # Selectores CSS para identificar campos en el formulario
    username_selector = models.CharField(
        max_length=200,
        default='input[name="username"], input[name="email"], input[type="email"]',
        help_text="Selector CSS para el campo de usuario"
    )
    password_selector = models.CharField(
        max_length=200,
        default='input[name="password"], input[type="password"]',
        help_text="Selector CSS para el campo de contraseña"
    )
    
    # Configuraciones adicionales
    wait_time = models.PositiveIntegerField(
        default=2,
        help_text="Tiempo de espera en segundos antes de autocompletar"
    )
    
    # Información adicional
    description = models.CharField(
        max_length=200, 
        blank=True,
        help_text="Descripción opcional de la credencial"
    )
    
    is_active = models.BooleanField(
        default=True,
        help_text="Si el sitio está activo para uso"
    )
    
    # Metadatos
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_used = models.DateTimeField(
        null=True, 
        blank=True,
        help_text="Última vez que se usó esta credencial"
    )
    
    class Meta:
        verbose_name = 'Sitio Autorizado'
        verbose_name_plural = 'Sitios Autorizados'
        unique_together = ['owner', 'url', 'username']
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} - {self.username}"
    
    def get_domain(self):
        """Extrae el dominio de la URL"""
        from urllib.parse import urlparse
        return urlparse(self.url).netloc
    
    def mark_as_used(self):
        """Marca la credencial como usada recientemente"""
        self.last_used = timezone.now()
        self.save(update_fields=['last_used'])


class AccessToken(models.Model):
    """
    Tokens temporales para acceso a múltiples credenciales desde la extensión
    """
    owner = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='access_tokens',
        help_text="Usuario que genera el token"
    )
    
    # Sitios autorizados para este token (relación muchos a muchos)
    authorized_sites = models.ManyToManyField(
        AuthorizedSite,
        related_name='access_tokens',
        help_text="Sitios a los que da acceso este token"
    )
    
    # Token y configuración
    token = models.CharField(
        max_length=255, 
        unique=True,
        help_text="Token JWT o string único para autenticación"
    )
    
    # Configuración de expiración y límites
    expires_at = models.DateTimeField(
        help_text="Fecha y hora de expiración del token"
    )
    max_uses = models.IntegerField(
        default=-1,
        help_text="Máximo número de usos (-1 = ilimitado)"
    )
    current_uses = models.IntegerField(
        default=0,
        help_text="Número actual de usos"
    )
    
    # Información del colaborador
    collaborator_email = models.EmailField(
        blank=True,
        help_text="Email del colaborador que usará este token"
    )
    collaborator_name = models.CharField(
        max_length=100,
        blank=True,
        help_text="Nombre del colaborador"
    )
    
    # Estados
    is_active = models.BooleanField(
        default=True,
        help_text="Si el token está activo"
    )
    
    # Metadatos
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(
        null=True, 
        blank=True,
        help_text="Última vez que se usó este token"
    )
    
    class Meta:
        verbose_name = 'Token de Acceso'
        verbose_name_plural = 'Tokens de Acceso'
        ordering = ['-created_at']
    
    def __str__(self):
        sites_count = self.authorized_sites.count()
        return f"Token para {sites_count} sitio{'s' if sites_count != 1 else ''} - {self.collaborator_email or 'Sin asignar'}"
    
    def is_expired(self):
        """Verifica si el token ha expirado"""
        return timezone.now() > self.expires_at
    
    def is_usage_exceeded(self):
        """Verifica si se ha excedido el límite de usos"""
        if self.max_uses == -1:
            return False
        return self.current_uses >= self.max_uses
    
    def is_valid(self):
        """Verifica si el token es válido (activo, no expirado, no excedido)"""
        return (
            self.is_active and 
            not self.is_expired() and 
            not self.is_usage_exceeded()
        )
    
    def increment_usage(self):
        """Incrementa el contador de usos y actualiza last_used"""
        self.current_uses += 1
        self.last_used = timezone.now()
        self.save(update_fields=['current_uses', 'last_used'])
    
    def get_remaining_uses(self):
        """Retorna el número de usos restantes"""
        if self.max_uses == -1:
            return "Ilimitado"
        return max(0, self.max_uses - self.current_uses)
    
    def get_time_remaining(self):
        """Retorna el tiempo restante antes de la expiración"""
        if self.is_expired():
            return "Expirado"
        remaining = self.expires_at - timezone.now()
        if remaining.days > 0:
            return f"{remaining.days} días"
        elif remaining.seconds > 3600:
            hours = remaining.seconds // 3600
            return f"{hours} horas"
        else:
            minutes = remaining.seconds // 60
            return f"{minutes} minutos"
    
    def get_authorized_sites_list(self):
        """Retorna lista de nombres de sitios autorizados"""
        return [site.name for site in self.authorized_sites.all()]
    
    def can_access_site(self, site_url):
        """Verifica si el token puede acceder a un sitio específico"""
        from urllib.parse import urlparse
        request_domain = urlparse(site_url).netloc
        
        for site in self.authorized_sites.filter(is_active=True):
            authorized_domain = urlparse(site.url).netloc
            if request_domain == authorized_domain:
                return site
        return None
    
    @classmethod
    def generate_token(cls):
        """Genera un token único"""
        return secrets.token_urlsafe(32)
    
    def save(self, *args, **kwargs):
        # Generar token automáticamente si no existe
        if not self.token:
            self.token = self.generate_token()
        super().save(*args, **kwargs)


class AccessLog(models.Model):
    """
    Registro de accesos y uso de tokens para auditoría
    """
    token = models.ForeignKey(
        AccessToken, 
        on_delete=models.CASCADE, 
        related_name='access_logs',
        help_text="Token usado en este acceso"
    )
    site = models.ForeignKey(
        AuthorizedSite,
        on_delete=models.CASCADE,
        related_name='access_logs',
        help_text="Sitio específico accedido",
        null=True,
        blank=True
    )
    
    # Información del acceso
    site_url = models.URLField(
        max_length=500,
        help_text="URL donde se usó el token"
    )
    action = models.CharField(
        max_length=50,
        choices=[
            ('validate', 'Validación de Token'),
            ('credential_request', 'Solicitud de Credenciales'),
            ('autocomplete', 'Autocompletado Realizado'),
            ('error', 'Error en el Proceso'),
        ],
        default='validate',
        help_text="Tipo de acción realizada"
    )
    
    # Información técnica
    ip_address = models.GenericIPAddressField(
        help_text="Dirección IP desde donde se realizó el acceso"
    )
    user_agent = models.TextField(
        blank=True,
        help_text="User Agent del navegador"
    )
    
    # Resultado
    success = models.BooleanField(
        default=True,
        help_text="Si la operación fue exitosa"
    )
    error_message = models.TextField(
        blank=True,
        help_text="Mensaje de error si hubo algún problema"
    )
    
    # Información adicional
    response_time = models.FloatField(
        null=True,
        blank=True,
        help_text="Tiempo de respuesta en segundos"
    )
    
    # Metadatos
    timestamp = models.DateTimeField(
        auto_now_add=True,
        help_text="Fecha y hora del acceso"
    )
    
    class Meta:
        verbose_name = 'Log de Acceso'
        verbose_name_plural = 'Logs de Acceso'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['token', 'timestamp']),
            models.Index(fields=['ip_address']),
        ]
    
    def __str__(self):
        site_name = self.site.name if self.site else "Sitio desconocido"
        return f"{self.get_action_display()} - {site_name} - {self.timestamp}"
    
    def get_credential_info(self):
        """Retorna información de la credencial asociada"""
        if self.site:
            return {
                'site_name': self.site.name,
                'username': self.site.username,
                'owner': self.site.owner.email
            }
        return {'site_name': 'N/A', 'username': 'N/A', 'owner': 'N/A'}


class TokenUsageStats(models.Model):
    """
    Estadísticas agregadas de uso de tokens por día (para optimizar consultas)
    """
    date = models.DateField(
        help_text="Fecha de las estadísticas"
    )
    owner = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='token_stats',
        help_text="Usuario propietario de los tokens"
    )
    
    # Estadísticas del día
    total_accesses = models.PositiveIntegerField(
        default=0,
        help_text="Total de accesos en el día"
    )
    successful_accesses = models.PositiveIntegerField(
        default=0,
        help_text="Accesos exitosos"
    )
    failed_accesses = models.PositiveIntegerField(
        default=0,
        help_text="Accesos fallidos"
    )
    unique_tokens_used = models.PositiveIntegerField(
        default=0,
        help_text="Tokens únicos utilizados"
    )
    unique_sites_accessed = models.PositiveIntegerField(
        default=0,
        help_text="Sitios únicos accedidos"
    )
    
    # Metadatos
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Estadística de Uso'
        verbose_name_plural = 'Estadísticas de Uso'
        unique_together = ['date', 'owner']
        ordering = ['-date']
    
    def __str__(self):
        return f"Stats {self.date} - {self.owner.email} ({self.total_accesses} accesos)"