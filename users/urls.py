from django.urls import path
from .views import (
    CustomLoginView, 
    SignUpView, 
    CustomLogoutView,
    # CRUD de usuarios
    user_list_view,
    user_detail_view,
    user_edit_view,
    user_delete_view,
    user_toggle_active_view,
    user_toggle_staff_view,
)

app_name = 'users'

urlpatterns = [
    # Autenticación
    path('login/', CustomLoginView.as_view(), name='login'),
    path('signup/', SignUpView.as_view(), name='signup'),
    path('logout/', CustomLogoutView.as_view(), name='logout'),
    
    # CRUD de usuarios (solo staff)
    path('manage/', user_list_view, name='user_list'),
    path('manage/<int:pk>/', user_detail_view, name='user_detail'),
    path('manage/<int:pk>/edit/', user_edit_view, name='user_edit'),
    path('manage/<int:pk>/delete/', user_delete_view, name='user_delete'),
    path('manage/<int:pk>/toggle-active/', user_toggle_active_view, name='user_toggle_active'),
    path('manage/<int:pk>/toggle-staff/', user_toggle_staff_view, name='user_toggle_staff'),
]