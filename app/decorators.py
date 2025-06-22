from functools import wraps
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import AppRegistry, UserAppAccess


def saas_access_required(app_name):
    """
    Decorador que verifica si el usuario tiene acceso a una app SAAS específica
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapper(request, *args, **kwargs):
            try:
                # Buscar la app en el registro
                app = AppRegistry.objects.get(name=app_name, is_active=True)
                
                # Si es app administrativa, verificar que sea staff
                if app.app_type == 'admin':
                    if not request.user.is_staff:
                        messages.error(request, f'No tienes permisos para acceder a {app.display_name}')
                        return redirect('app:dashboard')
                    return view_func(request, *args, **kwargs)
                
                # Si es app SAAS, verificar acceso específico
                elif app.app_type == 'saas':
                    has_access = UserAppAccess.objects.filter(
                        user=request.user,
                        app=app,
                        is_active=True
                    ).exists()
                    
                    if not has_access:
                        # Redirigir a template de no suscripción
                        context = {
                            'app': app,
                            'contact_email': 'contacto@forgeapp.cl'
                        }
                        return render(request, f'{app_name}/no_subscription.html', context)
                    
                    return view_func(request, *args, **kwargs)
                
            except AppRegistry.DoesNotExist:
                messages.error(request, f'La aplicación {app_name} no existe o no está disponible')
                return redirect('app:dashboard')
        
        return wrapper
    return decorator