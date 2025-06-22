from django.shortcuts import render
from app.decorators import saas_access_required

@saas_access_required('iatp')
def teapot_view(request):
    """Vista que muestra un divertido error 418 - I'm a teapot"""
    context = {
        'error_code': '418',
        'error_message': "I'm a teapot",
        'user': request.user,
    }
    return render(request, 'iatp/teapot.html', context, status=418)