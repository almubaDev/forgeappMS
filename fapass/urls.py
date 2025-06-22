from django.urls import path
from .views import (
    # Dashboard
    fapass_dashboard,
    
    # Sitios autorizados
    site_list,
    site_create,
    site_edit,
    site_delete,
    get_site_password,
    
    # Tokens de acceso
    token_list,
    token_create,
    token_delete,
    
    # Herramientas
    password_generator,
    generate_password_ajax,
    
    # API para extensión
    api_validate_token,
    api_get_credentials,
    api_log_usage,
)

app_name = 'fapass'

urlpatterns = [
    # Dashboard principal
    path('', fapass_dashboard, name='dashboard'),
    
    # === SITIOS AUTORIZADOS ===
    path('sites/', site_list, name='site_list'),
    path('sites/create/', site_create, name='site_create'),
    path('sites/<int:pk>/edit/', site_edit, name='site_edit'),
    path('sites/<int:pk>/delete/', site_delete, name='site_delete'),
    path('sites/<int:pk>/get-password/', get_site_password, name='get_site_password'),
    
    # === TOKENS DE ACCESO ===
    path('tokens/', token_list, name='token_list'),
    path('tokens/create/', token_create, name='token_create'),
    path('tokens/<int:pk>/delete/', token_delete, name='token_delete'),
    
    # === HERRAMIENTAS ===
    path('tools/password-generator/', password_generator, name='password_generator'),
    path('tools/password-generator/ajax/', generate_password_ajax, name='generate_password_ajax'),
    
    # === API PARA EXTENSIÓN ===
    path('api/validate-token/', api_validate_token, name='api_validate_token'),
    path('api/get-credentials/', api_get_credentials, name='api_get_credentials'),
    path('api/log-usage/', api_log_usage, name='api_log_usage'),
]