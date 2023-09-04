
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt import views as jwt_views
from authentication.views import CustomTokenObtainPairView

from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('',include('authentication.urls')),
    path('token/', 
          CustomTokenObtainPairView.as_view(), 
          name ='token_obtain_pair'),
     path('token/refresh/', 
          jwt_views.TokenRefreshView.as_view(), 
          name ='token_refresh')
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
