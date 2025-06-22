from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.views import LoginView
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.urls import reverse_lazy
from django.views.generic import CreateView
from django.views import View
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.core.exceptions import PermissionDenied
from .forms import CustomUserCreationForm, CustomAuthenticationForm

User = get_user_model()


def is_staff_user(user):
    """Helper function to check if user is staff"""
    return user.is_staff


class CustomLoginView(LoginView):
    form_class = CustomAuthenticationForm
    template_name = 'users/login.html'
    redirect_authenticated_user = True
    
    def get_success_url(self):
        return reverse_lazy('app:dashboard')
    
    def form_invalid(self, form):
        messages.error(self.request, 'Credenciales incorrectas')
        return super().form_invalid(form)


class SignUpView(CreateView):
    form_class = CustomUserCreationForm
    template_name = 'users/register.html'
    success_url = reverse_lazy('users:user_list')
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['request_user'] = self.request.user if self.request.user.is_authenticated else None
        return kwargs
    
    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, 'Usuario creado exitosamente')
        return response
    
    def form_invalid(self, form):
        messages.error(self.request, 'Por favor corrige los errores en el formulario')
        return super().form_invalid(form)


class CustomLogoutView(View):
    def get(self, request):
        logout(request)
        messages.success(request, 'Has cerrado sesión exitosamente')
        return redirect('users:login')
    
    def post(self, request):
        logout(request)
        messages.success(request, 'Has cerrado sesión exitosamente')
        return redirect('users:login')


# === CRUD DE USUARIOS (SOLO STAFF) ===

@login_required
@user_passes_test(is_staff_user)
def user_list_view(request):
    """Lista todos los usuarios del sistema (EXCLUYENDO superusuarios para staff)"""
    
    # Si es superuser, ve todos. Si es staff, NO ve superusuarios
    if request.user.is_superuser:
        users = User.objects.all().order_by('-date_joined')
    else:
        users = User.objects.filter(is_superuser=False).order_by('-date_joined')
    
    # Búsqueda
    search = request.GET.get('search')
    if search:
        users = users.filter(
            Q(email__icontains=search) |
            Q(first_name__icontains=search) |
            Q(last_name__icontains=search)
        )
    
    # Filtros
    is_active = request.GET.get('is_active')
    if is_active:
        users = users.filter(is_active=is_active == 'true')
    
    is_staff = request.GET.get('is_staff')
    if is_staff:
        users = users.filter(is_staff=is_staff == 'true')
    
    context = {
        'users': users,
        'search': search,
        'is_active_filter': is_active,
        'is_staff_filter': is_staff,
    }
    return render(request, 'users/user_list.html', context)


@login_required
@user_passes_test(is_staff_user)
def user_detail_view(request, pk):
    """Ver detalles de un usuario y gestionar sus accesos a apps"""
    user_detail = get_object_or_404(User, pk=pk)
    
    # Staff no puede ver detalles de superusuarios
    if user_detail.is_superuser and not request.user.is_superuser:
        raise PermissionDenied("No tienes permisos para ver este usuario")
    
    # Importar aquí para evitar circular imports
    from app.models import AppRegistry, UserAppAccess
    
    # Obtener todas las apps SAAS disponibles
    saas_apps = AppRegistry.objects.filter(app_type='saas', is_active=True).order_by('display_name')
    
    # Obtener accesos actuales del usuario
    user_accesses = UserAppAccess.objects.filter(user=user_detail).values_list('app_id', flat=True)
    
    # Crear lista de apps con estado de acceso
    apps_with_access = []
    for app in saas_apps:
        apps_with_access.append({
            'app': app,
            'has_access': app.id in user_accesses
        })
    
    # Manejar POST para actualizar accesos
    if request.method == 'POST':
        selected_app_ids = request.POST.getlist('app_access')
        selected_app_ids = [int(app_id) for app_id in selected_app_ids]
        
        # Eliminar accesos que ya no están seleccionados
        UserAppAccess.objects.filter(
            user=user_detail,
            app__app_type='saas'
        ).exclude(app_id__in=selected_app_ids).delete()
        
        # Agregar nuevos accesos
        for app_id in selected_app_ids:
            UserAppAccess.objects.get_or_create(
                user=user_detail,
                app_id=app_id,
                defaults={
                    'granted_by': request.user,
                    'is_active': True
                }
            )
        
        messages.success(request, f'Accesos actualizados para {user_detail.email}')
        return redirect('users:user_detail', pk=user_detail.pk)
    
    context = {
        'user_detail': user_detail,
        'apps_with_access': apps_with_access,
    }
    return render(request, 'users/user_detail.html', context)


@login_required
@user_passes_test(is_staff_user)
def user_edit_view(request, pk):
    """Editar un usuario existente"""
    user_detail = get_object_or_404(User, pk=pk)
    
    # Staff no puede editar superusuarios
    if user_detail.is_superuser and not request.user.is_superuser:
        raise PermissionDenied("No tienes permisos para editar este usuario")
    
    if request.method == 'POST':
        # Crear formulario con datos actuales
        form_data = request.POST.copy()
        
        # Actualizar campos básicos
        user_detail.email = form_data.get('email', user_detail.email)
        user_detail.first_name = form_data.get('first_name', user_detail.first_name)
        user_detail.last_name = form_data.get('last_name', user_detail.last_name)
        user_detail.is_active = 'is_active' in form_data
        
        # Solo permitir cambiar is_staff si el usuario actual es superuser
        if request.user.is_superuser:
            user_detail.is_staff = 'is_staff' in form_data
        
        # Cambiar contraseña si se proporciona
        new_password = form_data.get('new_password')
        if new_password:
            user_detail.set_password(new_password)
        
        try:
            user_detail.save()
            messages.success(request, f'Usuario {user_detail.email} actualizado exitosamente')
            return redirect('users:user_detail', pk=user_detail.pk)
        except Exception as e:
            messages.error(request, f'Error al actualizar usuario: {str(e)}')
    
    context = {
        'user_detail': user_detail,
    }
    return render(request, 'users/user_edit.html', context)


@login_required
@user_passes_test(is_staff_user)
def user_delete_view(request, pk):
    """Eliminar un usuario"""
    user_detail = get_object_or_404(User, pk=pk)
    
    # Staff no puede eliminar superusuarios
    if user_detail.is_superuser and not request.user.is_superuser:
        raise PermissionDenied("No tienes permisos para eliminar este usuario")
    
    # No permitir auto-eliminación
    if user_detail == request.user:
        messages.error(request, 'No puedes eliminar tu propia cuenta')
        return redirect('users:user_list')
    
    if request.method == 'POST':
        user_email = user_detail.email
        user_detail.delete()
        messages.success(request, f'Usuario {user_email} eliminado exitosamente')
        return redirect('users:user_list')
    
    context = {
        'user_detail': user_detail,
    }
    return render(request, 'users/user_delete.html', context)


@login_required
@user_passes_test(is_staff_user)
def user_toggle_active_view(request, pk):
    """Activar/desactivar usuario"""
    user_detail = get_object_or_404(User, pk=pk)
    
    # Staff no puede activar/desactivar superusuarios
    if user_detail.is_superuser and not request.user.is_superuser:
        raise PermissionDenied("No tienes permisos para modificar este usuario")
    
    # No permitir desactivar la propia cuenta
    if user_detail == request.user:
        messages.error(request, 'No puedes desactivar tu propia cuenta')
        return redirect('users:user_list')
    
    user_detail.is_active = not user_detail.is_active
    user_detail.save()
    
    status = "activado" if user_detail.is_active else "desactivado"
    messages.success(request, f'Usuario {user_detail.email} {status} exitosamente')
    
    return redirect('users:user_list')


@login_required
@user_passes_test(is_staff_user)
def user_toggle_staff_view(request, pk):
    """Activar/desactivar permisos de staff (solo superusers)"""
    if not request.user.is_superuser:
        raise PermissionDenied('Solo los superusuarios pueden cambiar permisos de staff')
    
    user_detail = get_object_or_404(User, pk=pk)
    
    # No permitir quitar staff a uno mismo
    if user_detail == request.user:
        messages.error(request, 'No puedes quitar tus propios permisos de staff')
        return redirect('users:user_list')
    
    # No permitir modificar superusuarios
    if user_detail.is_superuser:
        messages.error(request, 'No puedes modificar permisos de superusuarios')
        return redirect('users:user_list')
    
    user_detail.is_staff = not user_detail.is_staff
    user_detail.save()
    
    status = "otorgados" if user_detail.is_staff else "removidos"
    messages.success(request, f'Permisos de staff {status} a {user_detail.email}')
    
    return redirect('users:user_list')