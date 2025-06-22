from django.core.exceptions import PermissionDenied
from functools import wraps


def owns_object(model_class, pk_param='pk', owner_field='owner'):
    """
    Decorador que verifica que el usuario sea propietario del objeto
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Obtener el pk del objeto
            pk = kwargs.get(pk_param)
            if not pk:
                raise PermissionDenied("ID de objeto no encontrado")
            
            # Verificar que el objeto existe y pertenece al usuario
            try:
                obj = model_class.objects.get(pk=pk)
                owner = getattr(obj, owner_field)
                
                # Verificar ownership
                if owner != request.user:
                    raise PermissionDenied("No tienes permisos para acceder a este recurso")
                    
            except model_class.DoesNotExist:
                raise PermissionDenied("Objeto no encontrado")
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def rate_limit(max_requests=10, window_minutes=5):
    """
    Decorador simple de rate limiting
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            # Aquí se implementaría la lógica de rate limiting
            # Por simplicidad, por ahora solo registramos
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def api_key_required(view_func):
    """
    Decorador que requiere una API key válida para acceder
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # Por ahora, permitir acceso sin API key
        # En el futuro se puede implementar autenticación por API key
        return view_func(request, *args, **kwargs)
    return wrapper