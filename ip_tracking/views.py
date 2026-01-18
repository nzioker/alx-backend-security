from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.http import require_POST
from django_ratelimit.decorators import ratelimit

@method_decorator(csrf_protect, name='dispatch')
@method_decorator(ratelimit(key='ip', rate='5/m', method='POST', group='login'), name='post')
@method_decorator(ratelimit(key='user', rate='10/m', method='POST', group='login'), name='post')
class LoginView(View):
    template_name = 'login.html'
    
    def get(self, request):
        form = AuthenticationForm()
        return render(request, self.template_name, {'form': form})
    
    def post(self, request):
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            
            if user is not None:
                login(request, user)
                return redirect('dashboard')
        
        return render(request, self.template_name, {'form': form})

# Example sensitive view with rate limiting
@ratelimit(key='ip', rate='10/m', group='sensitive')
@ratelimit(key='user', rate='20/m', group='sensitive')
def sensitive_data_view(request):
    return render(request, 'sensitive_data.html')

# Admin view with stricter limits
@ratelimit(key='ip', rate='5/m', group='admin')
@ratelimit(key='user', rate='10/m', group='admin')
def admin_dashboard(request):
    if not request.user.is_staff:
        return redirect('home')
    return render(request, 'admin_dashboard.html')
