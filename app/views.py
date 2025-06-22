from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.urls import reverse
from django.http import Http404
from django.core.exceptions import PermissionDenied
from django.db.models import Q, Count
from django.utils import timezone
from .models import AppRegistry, UserAppAccess, AppUsageLog
from .forms import AppRegistryForm, UserAppAccessForm, BulkUserAppAccessForm, AppAccessFilterForm


def is_staff_user(user):
    """Helper function to check if user is staff"""
    return user.is_staff


@login_required
def dashboard_view(request):
    """Dashboard principal que muestra las apps disponibles según permisos del usuario"""
    
    # Obtener apps disponibles para el usuario
    if request.user.is_staff:
        # Staff puede ver apps administrativas
        available_apps = AppRegistry.objects.filter(
            is_active=True,
            app_type='admin'
        ).order_by('order', 'display_name')
        
        # También puede ver SAAS apps a las que tiene acceso
        saas_apps = AppRegistry.objects.filter(
            is_active=True,
            app_type='saas',
            user_accesses__user=request.user,
            user_accesses__is_active=True
        ).order_by('order', 'display_name')
        
        available_apps = list(available_apps) + list(saas_apps)
    else:
        # Usuarios normales solo ven SAAS apps a las que tienen acceso
        available_apps = AppRegistry.objects.filter(
            is_active=True,
            app_type='saas',
            user_accesses__user=request.user,
            user_accesses__is_active=True
        ).order_by('order', 'display_name')
    
    # Estadísticas para mostrar en el header
    total_apps = len(available_apps)
    total_users = 1  # Por ahora solo el usuario actual
    
    context = {
        'user': request.user,
        'available_apps': available_apps,
        'total_apps': total_apps,
        'total_users': total_users,
    }
    return render(request, 'app/dashboard.html', context)


# === GESTIÓN DE APLICACIONES (SOLO STAFF) ===

@login_required
@user_passes_test(is_staff_user)
def app_registry_list_view(request):
    """Lista todas las aplicaciones registradas"""
    apps = AppRegistry.objects.all().order_by('order', 'display_name')
    
    context = {
        'apps': apps,
    }
    return render(request, 'app/admin/app_registry_list.html', context)


@login_required
@user_passes_test(is_staff_user)
def app_registry_create_view(request):
    """Crear nueva aplicación en el registro"""
    if request.method == 'POST':
        form = AppRegistryForm(request.POST)
        if form.is_valid():
            app = form.save()
            messages.success(request, f'Aplicación "{app.display_name}" creada exitosamente')
            return redirect('app:app_registry_list')
    else:
        form = AppRegistryForm()
    
    context = {
        'form': form,
        'title': 'Crear Nueva Aplicación'
    }
    return render(request, 'app/admin/app_registry_form.html', context)


@login_required
@user_passes_test(is_staff_user)
def app_registry_update_view(request, pk):
    """Editar aplicación existente"""
    app = get_object_or_404(AppRegistry, pk=pk)
    
    if request.method == 'POST':
        form = AppRegistryForm(request.POST, instance=app)
        if form.is_valid():
            app = form.save()
            messages.success(request, f'Aplicación "{app.display_name}" actualizada exitosamente')
            return redirect('app:app_registry_list')
    else:
        form = AppRegistryForm(instance=app)
    
    context = {
        'form': form,
        'app': app,
        'title': f'Editar {app.display_name}'
    }
    return render(request, 'app/admin/app_registry_form.html', context)


@login_required
@user_passes_test(is_staff_user)
def app_registry_delete_view(request, pk):
    """Eliminar aplicación"""
    app = get_object_or_404(AppRegistry, pk=pk)
    
    if request.method == 'POST':
        app_name = app.display_name
        app.delete()
        messages.success(request, f'Aplicación "{app_name}" eliminada exitosamente')
        return redirect('app:app_registry_list')
    
    context = {
        'app': app,
    }
    return render(request, 'app/admin/app_registry_delete.html', context)


# === GESTIÓN DE ACCESOS DE USUARIOS (SOLO STAFF) ===

@login_required
@user_passes_test(is_staff_user)
def user_access_list_view(request):
    """Lista todos los accesos de usuarios con filtros"""
    accesses = UserAppAccess.objects.select_related('user', 'app', 'granted_by').all()
    
    # Aplicar filtros si existen
    filter_form = AppAccessFilterForm(request.GET)
    if filter_form.is_valid():
        if filter_form.cleaned_data['user']:
            accesses = accesses.filter(user=filter_form.cleaned_data['user'])
        if filter_form.cleaned_data['app']:
            accesses = accesses.filter(app=filter_form.cleaned_data['app'])
        if filter_form.cleaned_data['app_type']:
            accesses = accesses.filter(app__app_type=filter_form.cleaned_data['app_type'])
        if filter_form.cleaned_data['is_active']:
            is_active = filter_form.cleaned_data['is_active'] == 'true'
            accesses = accesses.filter(is_active=is_active)
    
    context = {
        'accesses': accesses,
        'filter_form': filter_form,
    }
    return render(request, 'app/admin/user_access_list.html', context)


@login_required
@user_passes_test(is_staff_user)
def user_access_create_view(request):
    """Crear acceso individual para un usuario"""
    if request.method == 'POST':
        form = UserAppAccessForm(request.POST, request_user=request.user)
        if form.is_valid():
            access = form.save()
            messages.success(
                request, 
                f'Acceso otorgado a {access.user.email} para {access.app.display_name}'
            )
            return redirect('app:user_access_list')
    else:
        form = UserAppAccessForm(request_user=request.user)
    
    context = {
        'form': form,
        'title': 'Otorgar Acceso a Usuario'
    }
    return render(request, 'app/admin/user_access_form.html', context)


@login_required
@user_passes_test(is_staff_user)
def user_access_bulk_create_view(request):
    """Crear accesos masivos para múltiples usuarios"""
    if request.method == 'POST':
        form = BulkUserAppAccessForm(request.POST, request_user=request.user)
        if form.is_valid():
            users = form.cleaned_data['users']
            app = form.cleaned_data['app']
            expires_at = form.cleaned_data['expires_at']
            notes = form.cleaned_data['notes']
            
            created_count = 0
            for user in users:
                access, created = UserAppAccess.objects.get_or_create(
                    user=user,
                    app=app,
                    defaults={
                        'granted_by': request.user,
                        'expires_at': expires_at,
                        'notes': notes
                    }
                )
                if created:
                    created_count += 1
            
            messages.success(
                request, 
                f'Acceso otorgado a {created_count} usuarios para {app.display_name}'
            )
            return redirect('app:user_access_list')
    else:
        form = BulkUserAppAccessForm(request_user=request.user)
    
    context = {
        'form': form,
        'title': 'Otorgar Acceso Masivo'
    }
    return render(request, 'app/admin/user_access_bulk_form.html', context)


@login_required
@user_passes_test(is_staff_user)
def user_access_delete_view(request, pk):
    """Eliminar acceso de usuario"""
    access = get_object_or_404(UserAppAccess, pk=pk)
    
    if request.method == 'POST':
        user_email = access.user.email
        app_name = access.app.display_name
        access.delete()
        messages.success(
            request, 
            f'Acceso removido: {user_email} ya no puede acceder a {app_name}'
        )
        return redirect('app:user_access_list')
    
    context = {
        'access': access,
    }
    return render(request, 'app/admin/user_access_delete.html', context)


@login_required
@user_passes_test(is_staff_user)
def user_access_toggle_view(request, pk):
    """Activar/desactivar acceso de usuario"""
    access = get_object_or_404(UserAppAccess, pk=pk)
    
    access.is_active = not access.is_active
    access.save()
    
    status = "activado" if access.is_active else "desactivado"
    messages.success(
        request, 
        f'Acceso {status} para {access.user.email} en {access.app.display_name}'
    )
    
    return redirect('app:user_access_list')


# === ACCESO A APLICACIONES ===

@login_required
def app_access_view(request, app_name):
    """Vista para acceder a una aplicación específica con verificación de permisos"""
    
    # Buscar la aplicación
    try:
        app = AppRegistry.objects.get(name=app_name, is_active=True)
    except AppRegistry.DoesNotExist:
        messages.error(request, f'La aplicación "{app_name}" no existe o no está disponible')
        return redirect('app:dashboard')
    
    # Verificar permisos
    if not app.can_user_access(request.user):
        messages.error(request, f'No tienes permisos para acceder a {app.display_name}')
        return redirect('app:dashboard')
    
    # Registrar el acceso en el log
    AppUsageLog.objects.create(
        user=request.user,
        app=app,
        ip_address=request.META.get('REMOTE_ADDR'),
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    
    # Redirigir a la aplicación
    try:
        return redirect(app.url_name)
    except:
        messages.error(request, f'Error al acceder a {app.display_name}')
        return redirect('app:dashboard')