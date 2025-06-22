from django.urls import path
from .views import teapot_view

app_name = 'iatp'

urlpatterns = [
    path('', teapot_view, name='teapot'),
]