from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model

User = get_user_model()


class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Correo electrónico'
        })
    )
    first_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Nombre'
        })
    )
    last_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Apellido'
        })
    )
    is_staff = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        }),
        label='Es staff'
    )
    
    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'password1', 'password2', 'is_staff')
    
    def __init__(self, *args, **kwargs):
        self.request_user = kwargs.pop('request_user', None)
        super().__init__(*args, **kwargs)
        
        # Agregar clases CSS a los campos de contraseña
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Contraseña'
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirmar contraseña'
        })
        
        # Ocultar el campo is_staff si el usuario no es superuser
        if not (self.request_user and self.request_user.is_superuser):
            del self.fields['is_staff']


class CustomAuthenticationForm(AuthenticationForm):
    username = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Correo electrónico'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Contraseña'
        })
    )