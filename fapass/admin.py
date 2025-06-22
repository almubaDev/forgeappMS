from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import AuthorizedSite, StoredCredential, AccessToken, AccessLog, TokenUsageStats


@admin.register(AuthorizedSite)
class AuthorizedSiteAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'owner', 'get_domain', 'is_active', 
        'credentials_count', 'created_at'
    ]
    list_filter = ['is_active', 'created_at', 'owner']
    search_fields = ['name', 'url', 'owner__email']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('owner', 'name', 'url', 'login_url', 'is_active')
        }),
        ('Configuración de Selectores', {
            'fields': ('username_selector', 'password_selector', 'wait_time'),
            'classes': ('collapse',)
        }),
        ('Metadatos', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_domain(self, obj):
        return obj.get_domain()
    get_domain.short_description = 'Dominio'
    
    def credentials_count(self, obj):
        count = obj.credentials.count()
        if count > 0:
            url = reverse('admin:fapass_storedcredential_changelist')
            return format_html(
                '<a href="{}?site__id__exact={}">{} credenciales</a>',
                url, obj.id, count
            )
        return '0 credenciales'
    credentials_count.short_description = 'Credenciales'


@admin.register(StoredCredential)
class StoredCredentialAdmin(admin.ModelAdmin):
    list_display = [
        'username', 'site', 'owner', 'is_active', 
        'tokens_count', 'last_used', 'created_at'
    ]
    list_filter = ['is_active', 'created_at', 'last_used', 'site', 'owner']
    search_fields = ['username', 'description', 'site__name', 'owner__email']
    readonly_fields = ['encrypted_password', 'password_salt', 'created_at', 'updated_at', 'last_used']
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('owner', 'site', 'username', 'description', 'is_active')
        }),
        ('Datos Cifrados', {
            'fields': ('encrypted_password', 'password_salt'),
            'classes': ('collapse',),
            'description': 'Información cifrada - NO modificar manualmente'
        }),
        ('Metadatos', {
            'fields': ('created_at', 'updated_at', 'last_used'),
            'classes': ('collapse',)
        }),
    )
    
    def tokens_count(self, obj):
        count = obj.access_tokens.count()
        if count > 0:
            url = reverse('admin:fapass_accesstoken_changelist')
            return format_html(
                '<a href="{}?credential__id__exact={}">{} tokens</a>',
                url, obj.id, count
            )
        return '0 tokens'
    tokens_count.short_description = 'Tokens'


@admin.register(AccessToken)
class AccessTokenAdmin(admin.ModelAdmin):
    list_display = [
        'get_credential_info', 'collaborator_email', 'is_valid_status',
        'expires_at', 'usage_info', 'created_at'
    ]
    list_filter = [
        'is_active', 'created_at', 'expires_at', 
        'credential__site', 'credential__owner'
    ]
    search_fields = [
        'collaborator_email', 'collaborator_name', 
        'credential__username', 'credential__site__name'
    ]
    readonly_fields = [
        'token', 'created_at', 'last_used', 'get_time_remaining', 
        'get_remaining_uses', 'is_valid'
    ]
    
    fieldsets = (
        ('Token', {
            'fields': ('token',),
            'description': 'Token generado automáticamente'
        }),
        ('Credencial y Colaborador', {
            'fields': ('credential', 'collaborator_email', 'collaborator_name')
        }),
        ('Configuración', {
            'fields': ('expires_at', 'max_uses', 'is_active')
        }),
        ('Estado Actual', {
            'fields': (
                'current_uses', 'get_remaining_uses', 
                'get_time_remaining', 'is_valid'
            ),
            'classes': ('collapse',)
        }),
        ('Metadatos', {
            'fields': ('created_at', 'last_used'),
            'classes': ('collapse',)
        }),
    )
    
    def get_credential_info(self, obj):
        return f"{obj.credential.username} @ {obj.credential.site.name}"
    get_credential_info.short_description = 'Credencial'
    
    def is_valid_status(self, obj):
        if obj.is_valid():
            return format_html(
                '<span style="color: green;">✓ Válido</span>'
            )
        elif obj.is_expired():
            return format_html(
                '<span style="color: red;">⏰ Expirado</span>'
            )
        elif obj.is_usage_exceeded():
            return format_html(
                '<span style="color: orange;">🔒 Agotado</span>'
            )
        else:
            return format_html(
                '<span style="color: gray;">⚫ Inactivo</span>'
            )
    is_valid_status.short_description = 'Estado'
    
    def usage_info(self, obj):
        if obj.max_uses == -1:
            return f"{obj.current_uses} usos (ilimitado)"
        else:
            remaining = max(0, obj.max_uses - obj.current_uses)
            return f"{obj.current_uses}/{obj.max_uses} usos ({remaining} restantes)"
    usage_info.short_description = 'Uso'


@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display = [
        'timestamp', 'get_token_info', 'action', 'success',
        'ip_address', 'get_site_domain'
    ]
    list_filter = [
        'action', 'success', 'timestamp',
        'token__credential__site', 'token__credential__owner'
    ]
    search_fields = [
        'site_url', 'ip_address', 'token__collaborator_email',
        'token__credential__username', 'token__credential__site__name'
    ]
    readonly_fields = [
        'timestamp', 'token', 'site_url', 'action', 'ip_address',
        'user_agent', 'success', 'error_message', 'response_time'
    ]
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Información del Acceso', {
            'fields': ('timestamp', 'token', 'site_url', 'action', 'success')
        }),
        ('Información Técnica', {
            'fields': ('ip_address', 'user_agent', 'response_time'),
            'classes': ('collapse',)
        }),
        ('Errores', {
            'fields': ('error_message',),
            'classes': ('collapse',)
        }),
    )
    
    def get_token_info(self, obj):
        return f"{obj.token.collaborator_email or 'Sin email'} - {obj.token.credential}"
    get_token_info.short_description = 'Token/Usuario'
    
    def get_site_domain(self, obj):
        from urllib.parse import urlparse
        try:
            domain = urlparse(obj.site_url).netloc
            return domain
        except:
            return 'N/A'
    get_site_domain.short_description = 'Dominio'
    
    def has_add_permission(self, request):
        # No permitir crear logs manualmente
        return False
    
    def has_change_permission(self, request, obj=None):
        # Solo lectura
        return False


@admin.register(TokenUsageStats)
class TokenUsageStatsAdmin(admin.ModelAdmin):
    list_display = [
        'date', 'owner', 'total_accesses', 'successful_accesses',
        'failed_accesses', 'success_rate'
    ]
    list_filter = ['date', 'owner']
    search_fields = ['owner__email']
    readonly_fields = [
        'date', 'owner', 'total_accesses', 'successful_accesses',
        'failed_accesses', 'unique_tokens_used', 'unique_sites_accessed',
        'created_at', 'updated_at'
    ]
    date_hierarchy = 'date'
    
    fieldsets = (
        ('Información Básica', {
            'fields': ('date', 'owner')
        }),
        ('Estadísticas de Acceso', {
            'fields': (
                'total_accesses', 'successful_accesses', 'failed_accesses',
                'unique_tokens_used', 'unique_sites_accessed'
            )
        }),
        ('Metadatos', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def success_rate(self, obj):
        if obj.total_accesses == 0:
            return '0%'
        rate = (obj.successful_accesses / obj.total_accesses) * 100
        color = 'green' if rate >= 90 else 'orange' if rate >= 70 else 'red'
        return format_html(
            '<span style="color: {};">{:.1f}%</span>',
            color, rate
        )
    success_rate.short_description = 'Tasa de éxito'
    
    def has_add_permission(self, request):
        # No permitir crear estadísticas manualmente
        return False
    
    def has_change_permission(self, request, obj=None):
        # Solo lectura
        return False


# Configuración del admin site
admin.site.site_header = "Fapass - Administración"
admin.site.site_title = "Fapass Admin"
admin.site.index_title = "Panel de Control de Fapass"