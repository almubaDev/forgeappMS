from django.urls import path
from .views import (
    dashboard_view,
    # Vistas de gestión de aplicaciones
    app_registry_list_view,
    app_registry_create_view,
    app_registry_update_view,
    app_registry_delete_view,
    # Vistas de gestión de accesos
    user_access_list_view,
    user_access_create_view,
    user_access_bulk_create_view,
    user_access_delete_view,
    user_access_toggle_view,
    # Vista de acceso a aplicaciones
    app_access_view,
)

app_name = 'app'

urlpatterns = [
    # Dashboard principal
    path('dashboard/', dashboard_view, name='dashboard'),
    
    # Gestión de aplicaciones (solo staff)
    path('manage/apps/', app_registry_list_view, name='app_registry_list'),
    path('manage/apps/create/', app_registry_create_view, name='app_registry_create'),
    path('manage/apps/<int:pk>/edit/', app_registry_update_view, name='app_registry_update'),
    path('manage/apps/<int:pk>/delete/', app_registry_delete_view, name='app_registry_delete'),
    
    # Gestión de accesos de usuarios (solo staff)
    path('manage/access/', user_access_list_view, name='user_access_list'),
    path('manage/access/create/', user_access_create_view, name='user_access_create'),
    path('manage/access/bulk/', user_access_bulk_create_view, name='user_access_bulk_create'),
    path('manage/access/<int:pk>/delete/', user_access_delete_view, name='user_access_delete'),
    path('manage/access/<int:pk>/toggle/', user_access_toggle_view, name='user_access_toggle'),
    
    # Acceso a aplicaciones
    path('access/<str:app_name>/', app_access_view, name='app_access'),
]