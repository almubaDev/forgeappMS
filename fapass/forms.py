from django import forms
from django.contrib.auth import get_user_model
from django.core.validators import URLValidator
from django.utils import timezone
from datetime import timedelta
import secrets
import string
import re
from .models import AuthorizedSite, AccessToken

User = get_user_model()


class AuthorizedSiteForm(forms.ModelForm):
    """Formulario para crear/editar sitios autorizados con credenciales"""
    
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Contraseña para el sitio'
        }),
        help_text="La contraseña se cifrará automáticamente"
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirmar contraseña'
        }),
        help_text="Confirma la contraseña"
    )
    
    class Meta:
        model = AuthorizedSite
        fields = [
            'name', 'url', 'username', 'description',
            'username_selector', 'password_selector', 'wait_time', 'is_active'
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Ej: Banco Estado'
            }),
            'url': forms.URLInput(attrs={
                'class': 'form-control',
                'placeholder': 'https://www.bancoestado.cl'
            }),
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Usuario o email para el login'
            }),
            'description': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Descripción opcional (ej: Cuenta principal)'
            }),
            'username_selector': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'input[name="username"]'
            }),
            'password_selector': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'input[name="password"]'
            }),
            'wait_time': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 1,
                'max': 10,
                'value': 2
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        
        # Si estamos editando, no mostrar campos de contraseña
        if self.instance.pk:
            del self.fields['password']
            del self.fields['confirm_password']
    
    def clean_url(self):
        url = self.cleaned_data.get('url')
        if url:
            # Validar que la URL sea válida
            validator = URLValidator()
            try:
                validator(url)
            except:
                raise forms.ValidationError('Ingresa una URL válida')
            
            # Asegurar que tenga protocolo
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
        return url
    
    def clean(self):
        cleaned_data = super().clean()
        
        # Solo validar contraseñas si estamos creando
        if not self.instance.pk:
            password = cleaned_data.get('password')
            confirm_password = cleaned_data.get('confirm_password')
            
            if password and confirm_password:
                if password != confirm_password:
                    raise forms.ValidationError('Las contraseñas no coinciden')
        
        return cleaned_data
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.user:
            instance.owner = self.user
        
        # Solo procesar contraseña si estamos creando
        if not self.instance.pk and 'password' in self.cleaned_data:
            from .utils import encrypt_password
            password = self.cleaned_data['password']
            instance.encrypted_password, instance.password_salt = encrypt_password(password)
        
        if commit:
            instance.save()
        return instance


class AccessTokenForm(forms.ModelForm):
    """Formulario para crear tokens de acceso temporal con múltiples sitios"""
    
    DURATION_CHOICES = [
        (1, '1 hora'),
        (4, '4 horas'),
        (8, '8 horas'),
        (24, '1 día'),
        (72, '3 días'),
        (168, '1 semana'),
    ]
    
    duration_hours = forms.ChoiceField(
        choices=DURATION_CHOICES,
        initial=24,
        widget=forms.Select(attrs={'class': 'form-control'}),
        help_text="Duración del token antes de expirar"
    )
    
    authorized_sites = forms.ModelMultipleChoiceField(
        queryset=AuthorizedSite.objects.none(),
        widget=forms.CheckboxSelectMultiple,
        help_text="Selecciona los sitios a los que tendrá acceso este token"
    )
    
    class Meta:
        model = AccessToken
        fields = [
            'collaborator_email', 'collaborator_name', 'max_uses'
        ]
        widgets = {
            'collaborator_email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'email@colaborador.com'
            }),
            'collaborator_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Nombre del colaborador'
            }),
            'max_uses': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': -1,
                'value': -1,
                'placeholder': '-1 para ilimitado'
            })
        }
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        
        # Filtrar sitios solo del usuario actual
        if self.user:
            self.fields['authorized_sites'].queryset = AuthorizedSite.objects.filter(
                owner=self.user, is_active=True
            ).order_by('name')
    
    def clean_max_uses(self):
        max_uses = self.cleaned_data.get('max_uses')
        if max_uses is not None and max_uses < -1:
            raise forms.ValidationError('El valor debe ser -1 (ilimitado) o mayor a 0')
        return max_uses
    
    def clean_authorized_sites(self):
        sites = self.cleaned_data.get('authorized_sites')
        if not sites:
            raise forms.ValidationError('Debe seleccionar al menos un sitio')
        return sites
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.user:
            instance.owner = self.user
        
        # Calcular fecha de expiración
        duration_hours = int(self.cleaned_data['duration_hours'])
        instance.expires_at = timezone.now() + timedelta(hours=duration_hours)from django import forms
from django.contrib.auth import get_user_model
from django.core.validators import URLValidator
from django.utils import timezone
from datetime import timedelta
import secrets
import string
import re
from .models import AuthorizedSite, AccessToken

User = get_user_model()


class AuthorizedSiteForm(forms.ModelForm):
    """Formulario para crear/editar sitios autorizados con credenciales"""
    
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Contraseña para el sitio'
        }),
        help_text="La contraseña se cifrará automáticamente"
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirmar contraseña'
        }),
        help_text="Confirma la contraseña"
    )
    
    class Meta:
        model = AuthorizedSite
        fields = [
            'name', 'url', 'username', 'description',
            'username_selector', 'password_selector', 'wait_time', 'is_active'
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Ej: Banco Estado'
            }),
            'url': forms.URLInput(attrs={
                'class': 'form-control',
                'placeholder': 'https://www.bancoestado.cl'
            }),
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Usuario o email para el login'
            }),
            'description': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Descripción opcional (ej: Cuenta principal)'
            }),
            'username_selector': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'input[name="username"]'
            }),
            'password_selector': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'input[name="password"]'
            }),
            'wait_time': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': 1,
                'max': 10,
                'value': 2
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        
        # Si estamos editando, no mostrar campos de contraseña
        if self.instance.pk:
            del self.fields['password']
            del self.fields['confirm_password']
    
    def clean_url(self):
        url = self.cleaned_data.get('url')
        if url:
            # Validar que la URL sea válida
            validator = URLValidator()
            try:
                validator(url)
            except:
                raise forms.ValidationError('Ingresa una URL válida')
            
            # Asegurar que tenga protocolo
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
        return url
    
    def clean(self):
        cleaned_data = super().clean()
        
        # Solo validar contraseñas si estamos creando
        if not self.instance.pk:
            password = cleaned_data.get('password')
            confirm_password = cleaned_data.get('confirm_password')
            
            if password and confirm_password:
                if password != confirm_password:
                    raise forms.ValidationError('Las contraseñas no coinciden')
        
        return cleaned_data
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.user:
            instance.owner = self.user
        
        # Solo procesar contraseña si estamos creando
        if not self.instance.pk and 'password' in self.cleaned_data:
            from .utils import encrypt_password
            password = self.cleaned_data['password']
            instance.encrypted_password, instance.password_salt = encrypt_password(password)
        
        if commit:
            instance.save()
        return instance


class PasswordUpdateForm(forms.Form):
    """Formulario específico para actualizar contraseña de un sitio"""
    
    current_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Contraseña actual (para verificación)'
        }),
        help_text="Ingresa la contraseña actual para verificar"
    )
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nueva contraseña'
        }),
        help_text="La nueva contraseña para el sitio"
    )
    confirm_new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirmar nueva contraseña'
        })
    )
    
    def __init__(self, *args, **kwargs):
        self.site = kwargs.pop('site', None)
        super().__init__(*args, **kwargs)
    
    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_new_password = cleaned_data.get('confirm_new_password')
        
        if new_password and confirm_new_password:
            if new_password != confirm_new_password:
                raise forms.ValidationError('Las nuevas contraseñas no coinciden')
        
        return cleaned_data


class AccessTokenForm(forms.ModelForm):
    """Formulario para crear tokens de acceso temporal con múltiples sitios"""
    
    DURATION_CHOICES = [
        (1, '1 hora'),
        (4, '4 horas'),
        (8, '8 horas'),
        (24, '1 día'),
        (72, '3 días'),
        (168, '1 semana'),
    ]
    
    duration_hours = forms.ChoiceField(
        choices=DURATION_CHOICES,
        initial=24,
        widget=forms.Select(attrs={'class': 'form-control'}),
        help_text="Duración del token antes de expirar"
    )
    
    authorized_sites = forms.ModelMultipleChoiceField(
        queryset=AuthorizedSite.objects.none(),
        widget=forms.CheckboxSelectMultiple,
        help_text="Selecciona los sitios a los que tendrá acceso este token"
    )
    
    class Meta:
        model = AccessToken
        fields = [
            'collaborator_email', 'collaborator_name', 'max_uses'
        ]
        widgets = {
            'collaborator_email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'email@colaborador.com'
            }),
            'collaborator_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Nombre del colaborador'
            }),
            'max_uses': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': -1,
                'value': -1,
                'placeholder': '-1 para ilimitado'
            })
        }
    
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        
        # Filtrar sitios solo del usuario actual
        if self.user:
            self.fields['authorized_sites'].queryset = AuthorizedSite.objects.filter(
                owner=self.user, is_active=True
            ).order_by('name')
    
    def clean_max_uses(self):
        max_uses = self.cleaned_data.get('max_uses')
        if max_uses is not None and max_uses < -1:
            raise forms.ValidationError('El valor debe ser -1 (ilimitado) o mayor a 0')
        return max_uses
    
    def clean_authorized_sites(self):
        sites = self.cleaned_data.get('authorized_sites')
        if not sites:
            raise forms.ValidationError('Debe seleccionar al menos un sitio')
        return sites
    
    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.user:
            instance.owner = self.user
        
        # Calcular fecha de expiración
        duration_hours = int(self.cleaned_data['duration_hours'])
        instance.expires_at = timezone.now() + timedelta(hours=duration_hours)
        
        if commit:
            instance.save()
            # Agregar sitios autorizados (relación many-to-many)
            instance.authorized_sites.set(self.cleaned_data['authorized_sites'])
        
        return instance


class PasswordGeneratorForm(forms.Form):
    """Formulario para el generador de contraseñas seguras"""
    
    length = forms.IntegerField(
        initial=16,
        min_value=8,
        max_value=128,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': 8,
            'max': 128
        }),
        help_text="Longitud de la contraseña (8-128 caracteres)"
    )
    
    include_uppercase = forms.BooleanField(
        initial=True,
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Incluir mayúsculas (A-Z)"
    )
    
    include_lowercase = forms.BooleanField(
        initial=True,
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Incluir minúsculas (a-z)"
    )
    
    include_numbers = forms.BooleanField(
        initial=True,
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Incluir números (0-9)"
    )
    
    include_symbols = forms.BooleanField(
        initial=True,
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Incluir símbolos (!@#$%^&*)"
    )
    
    exclude_ambiguous = forms.BooleanField(
        initial=True,
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Excluir caracteres ambiguos (0, O, l, I)"
    )
    
    def clean(self):
        cleaned_data = super().clean()
        
        # Verificar que al menos una opción esté seleccionada
        options = [
            cleaned_data.get('include_uppercase'),
            cleaned_data.get('include_lowercase'),
            cleaned_data.get('include_numbers'),
            cleaned_data.get('include_symbols')
        ]
        
        if not any(options):
            raise forms.ValidationError(
                'Debe seleccionar al menos un tipo de carácter'
            )
        
        return cleaned_data
    
    def generate_password(self):
        """Genera una contraseña según las opciones seleccionadas"""
        if not self.is_valid():
            return None
        
        from .utils import generate_secure_password
        return generate_secure_password(**self.cleaned_data)


class TokenFilterForm(forms.Form):
    """Formulario para filtrar tokens de acceso"""
    
    STATUS_CHOICES = [
        ('', 'Todos los estados'),
        ('active', 'Activos'),
        ('expired', 'Expirados'),
        ('exhausted', 'Agotados'),
        ('inactive', 'Inactivos'),
    ]
    
    status = forms.ChoiceField(
        choices=STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    collaborator_email = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Buscar por email del colaborador'
        })
    )


class SiteFilterForm(forms.Form):
    """Formulario para filtrar sitios autorizados"""
    
    search = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Buscar por nombre, URL o usuario...'
        })
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