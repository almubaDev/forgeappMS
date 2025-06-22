from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, Http404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db.models import Q, Count, F
from django.utils import timezone
from django.core.paginator import Paginator
from django.urls import reverse
import json
from datetime import timedelta

from .models import AuthorizedSite, AccessToken, AccessLog
from .forms import (
    AuthorizedSiteForm, AccessTokenForm, 
    PasswordGeneratorForm, TokenFilterForm, SiteFilterForm
)
from .utils import encrypt_password, decrypt_password, generate_secure_password


# === DASHBOARD PRINCIPAL ===

@login_required
def fapass_dashboard(request):
    """Dashboard principal de Fapass"""
    
    # Estadísticas del usuario
    total_sites = AuthorizedSite.objects.filter(owner=request.user).count()
    active_sites = AuthorizedSite.objects.filter(owner=request.user, is_active=True).count()
    total_tokens = AccessToken.objects.filter(owner=request.user).count()
    active_tokens = AccessToken.objects.filter(
        owner=request.user,
        is_active=True,
        expires_at__gt=timezone.now()
    ).count()
    
    # Tokens que expiran pronto (próximas 24 horas)
    expiring_soon = AccessToken.objects.filter(
        owner=request.user,
        is_active=True,
        expires_at__lte=timezone.now() + timedelta(hours=24),
        expires_at__gt=timezone.now()
    ).count()
    
    # Últimos accesos (últimos 5)
    recent_logs = AccessLog.objects.filter(
        token__owner=request.user
    ).select_related('token', 'site').order_by('-timestamp')[:5]
    
    # Sitios más usados (top 5)
    popular_sites = AuthorizedSite.objects.filter(
        owner=request.user,
        access_logs__isnull=False
    ).annotate(
        usage_count=Count('access_logs')
    ).order_by('-usage_count')[:5]
    
    context = {
        'stats': {
            'total_sites': total_sites,
            'active_sites': active_sites,
            'total_tokens': total_tokens,
            'active_tokens': active_tokens,
            'expiring_soon': expiring_soon,
        },
        'recent_logs': recent_logs,
        'popular_sites': popular_sites,
    }
    
    return render(request, 'fapass/dashboard.html', context)


# === GESTIÓN DE SITIOS AUTORIZADOS ===

@login_required
def site_list(request):
    """Lista de sitios autorizados del usuario con sus credenciales"""
    
    # Aplicar filtros
    filter_form = SiteFilterForm(request.GET)
    sites = AuthorizedSite.objects.filter(owner=request.user)
    
    if filter_form.is_valid():
        search = filter_form.cleaned_data.get('search')
        if search:
            sites = sites.filter(
                Q(name__icontains=search) | 
                Q(url__icontains=search) | 
                Q(username__icontains=search)
            )
        
        is_active = filter_form.cleaned_data.get('is_active')
        if is_active:
            sites = sites.filter(is_active=is_active == 'true')
    
    sites = sites.order_by('name')
    
    # Paginación
    paginator = Paginator(sites, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'filter_form': filter_form,
    }
    
    return render(request, 'fapass/sites/list.html', context)


@login_required
def site_create(request):
    """Crear nuevo sitio autorizado con credenciales"""
    
    if request.method == 'POST':
        form = AuthorizedSiteForm(request.POST, user=request.user)
        if form.is_valid():
            site = form.save()
            messages.success(request, f'Sitio "{site.name}" creado exitosamente')
            return redirect('fapass:site_list')
    else:
        form = AuthorizedSiteForm(user=request.user)
    
    context = {
        'form': form,
        'title': 'Crear Nuevo Sitio',
        'action': 'create'
    }
    
    return render(request, 'fapass/sites/form.html', context)


@login_required
def site_edit(request, pk):
    """Editar sitio autorizado"""
    
    site = get_object_or_404(AuthorizedSite, pk=pk, owner=request.user)
    
    if request.method == 'POST':
        form = AuthorizedSiteForm(request.POST, instance=site, user=request.user)
        if form.is_valid():
            site = form.save()
            messages.success(request, f'Sitio "{site.name}" actualizado exitosamente')
            return redirect('fapass:site_list')
    else:
        form = AuthorizedSiteForm(instance=site, user=request.user)
    
    context = {
        'form': form,
        'site': site,
        'title': f'Editar {site.name}',
        'action': 'edit'
    }
    
    return render(request, 'fapass/sites/form.html', context)


@login_required
def site_delete(request, pk):
    """Eliminar sitio autorizado"""
    
    site = get_object_or_404(AuthorizedSite, pk=pk, owner=request.user)
    
    if request.method == 'POST':
        site_name = site.name
        site.delete()
        messages.success(request, f'Sitio "{site_name}" eliminado exitosamente')
        return redirect('fapass:site_list')
    
    context = {
        'site': site,
    }
    
    return render(request, 'fapass/sites/delete.html', context)


@login_required
def get_site_password(request, pk):
    """API para obtener contraseña descifrada de un sitio (AJAX)"""
    
    if request.method != 'POST':
        return JsonResponse({'error': 'Método no permitido'}, status=405)
    
    site = get_object_or_404(AuthorizedSite, pk=pk, owner=request.user)
    
    try:
        password = decrypt_password(site.encrypted_password, site.password_salt)
        return JsonResponse({'password': password, 'success': True})
    except Exception as e:
        return JsonResponse({'error': 'Error al descifrar contraseña', 'success': False})


# === GESTIÓN DE TOKENS DE ACCESO ===

@login_required
def token_list(request):
    """Lista de tokens de acceso del usuario"""
    
    # Aplicar filtros
    filter_form = TokenFilterForm(request.GET, user=request.user)
    tokens = AccessToken.objects.filter(owner=request.user).prefetch_related(
        'authorized_sites'
    )
    
    if filter_form.is_valid():
        status = filter_form.cleaned_data.get('status')
        if status:
            now = timezone.now()
            if status == 'active':
                tokens = tokens.filter(is_active=True, expires_at__gt=now)
            elif status == 'expired':
                tokens = tokens.filter(expires_at__lte=now)
            elif status == 'exhausted':
                tokens = tokens.exclude(max_uses=-1).filter(
                    current_uses__gte=F('max_uses')
                )
            elif status == 'inactive':
                tokens = tokens.filter(is_active=False)
        
        collaborator_email = filter_form.cleaned_data.get('collaborator_email')
        if collaborator_email:
            tokens = tokens.filter(collaborator_email__icontains=collaborator_email)
    
    tokens = tokens.order_by('-created_at')
    
    # Paginación
    paginator = Paginator(tokens, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'filter_form': filter_form,
    }
    
    return render(request, 'fapass/tokens/list.html', context)


@login_required
def token_create(request):
    """Crear nuevo token de acceso"""
    
    if request.method == 'POST':
        form = AccessTokenForm(request.POST, user=request.user)
        if form.is_valid():
            token = form.save()
            sites_names = ', '.join([site.name for site in token.authorized_sites.all()])
            messages.success(
                request,
                f'Token creado exitosamente para: {sites_names}. '
                f'Token: {token.token}'
            )
            return redirect('fapass:token_list')
    else:
        form = AccessTokenForm(user=request.user)
    
    context = {
        'form': form,
        'title': 'Crear Nuevo Token',
        'action': 'create'
    }
    
    return render(request, 'fapass/tokens/form.html', context)


@login_required
def token_delete(request, pk):
    """Eliminar token de acceso"""
    
    token = get_object_or_404(AccessToken, pk=pk, owner=request.user)
    
    if request.method == 'POST':
        sites_count = token.authorized_sites.count()
        token.delete()
        messages.success(request, f'Token para {sites_count} sitio(s) eliminado exitosamente')
        return redirect('fapass:token_list')
    
    context = {
        'token': token,
    }
    
    return render(request, 'fapass/tokens/delete.html', context)


# === HERRAMIENTAS ===

@login_required
def password_generator(request):
    """Generador de contraseñas seguras"""
    
    generated_password = None
    
    if request.method == 'POST':
        form = PasswordGeneratorForm(request.POST)
        if form.is_valid():
            generated_password = form.generate_password()
    else:
        form = PasswordGeneratorForm()
    
    context = {
        'form': form,
        'generated_password': generated_password,
    }
    
    return render(request, 'fapass/tools/password_generator.html', context)


@login_required
def generate_password_ajax(request):
    """Generar contraseña vía AJAX"""
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            password = generate_secure_password(
                length=data.get('length', 16),
                include_uppercase=data.get('include_uppercase', True),
                include_lowercase=data.get('include_lowercase', True),
                include_numbers=data.get('include_numbers', True),
                include_symbols=data.get('include_symbols', True),
                exclude_ambiguous=data.get('exclude_ambiguous', True)
            )
            return JsonResponse({'password': password, 'success': True})
        except Exception as e:
            return JsonResponse({'error': str(e), 'success': False})
    
    return JsonResponse({'error': 'Método no permitido', 'success': False})


# === API PARA LA EXTENSIÓN ===

@csrf_exempt
@require_http_methods(["POST"])
def api_validate_token(request):
    """API: Validar token de acceso desde la extensión"""
    
    try:
        data = json.loads(request.body)
        token_string = data.get('token')
        site_url = data.get('site_url')
        
        if not token_string or not site_url:
            return JsonResponse({
                'valid': False,
                'error': 'Token y URL del sitio son requeridos'
            })
        
        # Buscar token
        try:
            token = AccessToken.objects.get(token=token_string)
        except AccessToken.DoesNotExist:
            return JsonResponse({
                'valid': False,
                'error': 'Token no encontrado'
            })
        
        # Validar token
        if not token.is_valid():
            return JsonResponse({
                'valid': False,
                'error': 'Token expirado o inválido'
            })
        
        # Verificar que la URL corresponda a un sitio autorizado
        authorized_site = token.can_access_site(site_url)
        if not authorized_site:
            return JsonResponse({
                'valid': False,
                'error': 'URL no autorizada para este token'
            })
        
        # Registrar acceso
        AccessLog.objects.create(
            token=token,
            site=authorized_site,
            site_url=site_url,
            action='validate',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )
        
        return JsonResponse({
            'valid': True,
            'site_name': authorized_site.name,
            'username_selector': authorized_site.username_selector,
            'password_selector': authorized_site.password_selector,
            'wait_time': authorized_site.wait_time
        })
        
    except Exception as e:
        return JsonResponse({
            'valid': False,
            'error': f'Error del servidor: {str(e)}'
        })


@csrf_exempt
@require_http_methods(["POST"])
def api_get_credentials(request):
    """API: Obtener credenciales para autocompletar"""
    
    try:
        data = json.loads(request.body)
        token_string = data.get('token')
        site_url = data.get('site_url')
        
        if not token_string or not site_url:
            return JsonResponse({
                'success': False,
                'error': 'Token y URL del sitio son requeridos'
            })
        
        # Buscar y validar token
        try:
            token = AccessToken.objects.get(token=token_string)
        except AccessToken.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Token no encontrado'
            })
        
        if not token.is_valid():
            return JsonResponse({
                'success': False,
                'error': 'Token expirado o inválido'
            })
        
        # Verificar que puede acceder al sitio
        authorized_site = token.can_access_site(site_url)
        if not authorized_site:
            return JsonResponse({
                'success': False,
                'error': 'URL no autorizada para este token'
            })
        
        # Incrementar uso del token
        token.increment_usage()
        
        # Marcar sitio como usado
        authorized_site.mark_as_used()
        
        # Descifrar contraseña
        try:
            password = decrypt_password(
                authorized_site.encrypted_password,
                authorized_site.password_salt
            )
        except Exception as e:
            AccessLog.objects.create(
                token=token,
                site=authorized_site,
                site_url=site_url,
                action='credential_request',
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=False,
                error_message=f'Error al descifrar: {str(e)}'
            )
            return JsonResponse({
                'success': False,
                'error': 'Error al acceder a las credenciales'
            })
        
        # Registrar acceso exitoso
        AccessLog.objects.create(
            token=token,
            site=authorized_site,
            site_url=site_url,
            action='credential_request',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )
        
        return JsonResponse({
            'success': True,
            'username': authorized_site.username,
            'password': password,
            'remaining_uses': token.get_remaining_uses()
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error del servidor: {str(e)}'
        })


@csrf_exempt
@require_http_methods(["POST"])
def api_log_usage(request):
    """API: Registrar uso de credenciales"""
    
    try:
        data = json.loads(request.body)
        token_string = data.get('token')
        site_url = data.get('site_url')
        success = data.get('success', True)
        error_message = data.get('error_message', '')
        
        if not token_string or not site_url:
            return JsonResponse({
                'logged': False,
                'error': 'Token y URL del sitio son requeridos'
            })
        
        # Buscar token
        try:
            token = AccessToken.objects.get(token=token_string)
        except AccessToken.DoesNotExist:
            return JsonResponse({
                'logged': False,
                'error': 'Token no encontrado'
            })
        
        # Buscar sitio autorizado
        authorized_site = token.can_access_site(site_url)
        
        # Registrar uso
        AccessLog.objects.create(
            token=token,
            site=authorized_site,
            site_url=site_url,
            action='autocomplete',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=success,
            error_message=error_message
        )
        
        return JsonResponse({
            'logged': True,
            'message': 'Uso registrado exitosamente'
        })
        
    except Exception as e:
        return JsonResponse({
            'logged': False,
            'error': f'Error del servidor: {str(e)}'
        })