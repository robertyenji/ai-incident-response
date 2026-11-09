from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from incidents.views import DemoLoginView

urlpatterns = [
    path('admin/', admin.site.urls),
    # Auth
    path('login/', DemoLoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    # App
    path('', include('incidents.urls')),
]
