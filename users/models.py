from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.base_user import BaseUserManager
from django.db import models
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('El email es obligatorio')
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('El superuser debe tener is_staff=True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('El superuser debe tener is_superuser=True')
        
        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, verbose_name='Correo electrónico')
    first_name = models.CharField(max_length=30, blank=True, verbose_name='Nombre')
    last_name = models.CharField(max_length=30, blank=True, verbose_name='Apellido')
    is_active = models.BooleanField(default=True, verbose_name='Activo')
    is_staff = models.BooleanField(default=False, blank=True, verbose_name='Es staff')
    date_joined = models.DateTimeField(default=timezone.now, verbose_name='Fecha de registro')
    
    objects = CustomUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    class Meta:
        verbose_name = 'Usuario'
        verbose_name_plural = 'Usuarios'
    
    def __str__(self):
        return self.email
    
    def get_full_name(self):
        return f'{self.first_name} {self.last_name}'.strip()
    
    def get_short_name(self):
        return self.first_name