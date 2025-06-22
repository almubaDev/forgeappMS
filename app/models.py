from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()


class AppRegistry(models.Model):
    """Registro de todas las aplicaciones disponibles en el sistema"""
    
    APP_TYPE_CHOICES = [
        ('admin', 'Administrativa'),
        ('saas', 'Micro SAAS'),
    ]
    
    name = models.CharField(
        max_length=100, 
        unique=True,
        help_text="Nombre técnico de la app (ej: 'iatp', 'users')"
    )
    display_name = models.CharField(
        max_length=100,
        help_text="Nombre que se muestra al usuario"
    )
    description = models.TextField(
        blank=True,
        help_text="Descripción de la funcionalidad de la app"
    )
    icon = models.CharField(
        max_length=50,
        default='fas fa-cube',
        help_text="Clase CSS del icono (Font Awesome)"
    )
    app_type = models.CharField(
        max_length=20,
        choices=APP_TYPE_CHOICES,
        help_text="Tipo de aplicación"
    )
    url_name = models.CharField(
        max_length=100,
        help_text="Nombre de la URL para acceder (ej: 'iatp:teapot')"
    )
    color = models.CharField(
        max_length=20,
        default='forge-blue',
        help_text="Color del tema de la app"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Si la app está disponible para uso"
    )
    order = models.PositiveIntegerField(
        default=0,
        help_text="Orden de aparición en el dashboard"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Aplicación Registrada'
        verbose_name_plural = 'Aplicaciones Registradas'
        ordering = ['order', 'display_name']
    
    def __str__(self):
        return f"{self.display_name} ({self.get_app_type_display()})"
    
    def can_user_access(self, user):
        """Verifica si un usuario puede acceder a esta app"""
        if not self.is_active:
            return False
            
        if self.app_type == 'admin':
            return user.is_staff
        else:  # saas
            return UserAppAccess.objects.filter(user=user, app=self).exists()


class UserAppAccess(models.Model):
    """Control de acceso de usuarios a aplicaciones Micro SAAS"""
    
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE,
        related_name='app_accesses'
    )
    app = models.ForeignKey(
        AppRegistry, 
        on_delete=models.CASCADE,
        related_name='user_accesses'
    )
    granted_at = models.DateTimeField(auto_now_add=True)
    granted_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='granted_accesses',
        help_text="Usuario que otorgó el acceso"
    )
    expires_at = models.DateTimeField(
        null=True, 
        blank=True,
        help_text="Fecha de expiración del acceso (opcional)"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Si el acceso está activo"
    )
    notes = models.TextField(
        blank=True,
        help_text="Notas sobre el acceso otorgado"
    )
    
    class Meta:
        verbose_name = 'Acceso a Aplicación'
        verbose_name_plural = 'Accesos a Aplicaciones'
        unique_together = ['user', 'app']
        ordering = ['-granted_at']
    
    def __str__(self):
        return f"{self.user.email} -> {self.app.display_name}"
    
    def is_expired(self):
        """Verifica si el acceso ha expirado"""
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Verifica si el acceso es válido (activo y no expirado)"""
        return self.is_active and not self.is_expired()


class AppUsageLog(models.Model):
    """Log de uso de aplicaciones para estadísticas"""
    
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE,
        related_name='app_usage_logs'
    )
    app = models.ForeignKey(
        AppRegistry, 
        on_delete=models.CASCADE,
        related_name='usage_logs'
    )
    accessed_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        verbose_name = 'Log de Uso de App'
        verbose_name_plural = 'Logs de Uso de Apps'
        ordering = ['-accessed_at']
    
    def __str__(self):
        return f"{self.user.email} usó {self.app.display_name} - {self.accessed_at}"