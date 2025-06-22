from django import forms
from django.contrib.auth import get_user_model
from .models import AppRegistry, UserAppAccess

User = get_user_model()


class AppRegistryForm(forms.ModelForm):
    """Formulario para crear/editar aplicaciones en el registro"""
    
    class Meta:
        model = AppRegistry
        fields = [
            'name', 'display_name', 'description', 'icon', 
            'app_type', 'url_name', 'color', 'is_active', 'order'
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Nombre técnico (ej: iatp)'
            }),
            'display_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Nombre para mostrar'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Descripción de la aplicación'
            }),
            'icon': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'fas fa-coffee'
            }),
            'app_type': forms.Select(attrs={
                'class': 'form-control'
            }),
            'url_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'iatp:teapot'
            }),
            'color': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'forge-blue'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'order': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 0
            })
        }


class UserAppAccessForm(forms.ModelForm):
    """Formulario para otorgar acceso a usuarios a aplicaciones SAAS"""
    
    user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        widget=forms.Select(attrs={'class': 'form-control'}),
        empty_label="Seleccionar usuario"
    )
    
    app = forms.ModelChoiceField(
        queryset=AppRegistry.objects.filter(app_type='saas', is_active=True),
        widget=forms.Select(attrs={'class': 'form-control'}),
        empty_label="Seleccionar aplicación"
    )
    
    class Meta:
        model = UserAppAccess
        fields = ['user', 'app', 'expires_at', 'notes']
        widgets = {
            'expires_at': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local'
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Notas sobre este acceso (opcional)'
            })
        }
    
    def __init__(self, *args, **kwargs):
        self.request_user = kwargs.pop('request_user', None)
        super().__init__(*args, **kwargs)
        
        # Excluir al usuario actual de la lista si es necesario
        if self.request_user:
            self.fields['user'].queryset = self.fields['user'].queryset.exclude(
                id=self.request_user.id
            )
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.request_user:
            instance.granted_by = self.request_user
        if commit:
            instance.save()
        return instance


class BulkUserAppAccessForm(forms.Form):
    """Formulario para otorgar acceso masivo a múltiples usuarios"""
    
    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True),
        widget=forms.CheckboxSelectMultiple,
        label="Usuarios"
    )
    
    app = forms.ModelChoiceField(
        queryset=AppRegistry.objects.filter(app_type='saas', is_active=True),
        widget=forms.Select(attrs={'class': 'form-control'}),
        empty_label="Seleccionar aplicación"
    )
    
    expires_at = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'class': 'form-control',
            'type': 'datetime-local'
        }),
        label="Fecha de expiración (opcional)"
    )
    
    notes = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Notas sobre estos accesos'
        }),
        label="Notas"
    )
    
    def __init__(self, *args, **kwargs):
        self.request_user = kwargs.pop('request_user', None)
        super().__init__(*args, **kwargs)


class AppAccessFilterForm(forms.Form):
    """Formulario para filtrar accesos en la vista de administración"""
    
    user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        empty_label="Todos los usuarios",
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    app = forms.ModelChoiceField(
        queryset=AppRegistry.objects.filter(is_active=True),
        required=False,
        empty_label="Todas las aplicaciones",
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    app_type = forms.ChoiceField(
        choices=[('', 'Todos los tipos')] + AppRegistry.APP_TYPE_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    is_active = forms.ChoiceField(
        choices=[
            ('', 'Todos los estados'),
            ('true', 'Activos'),
            ('false', 'Inactivos')
        ],
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )