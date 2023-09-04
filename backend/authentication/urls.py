from django.urls import path
from . import views

urlpatterns = [
    path('signup', views.SignupView.as_view(), name ='signup'),
    path('home/', views.HomeView.as_view(), name ='home'),
    path('logout/', views.Signout.as_view(), name ='logout'),
    path('user-details', views.ProfileView.as_view(), name='user-details'),
    path('users', views.UserList.as_view(), name='users'),
    path('adduser', views.AddUser.as_view(), name='adduser'),
    path('deleteuser', views.DeleteUser.as_view(), name='deleteuser'),
    path('edituser', views.EditUser.as_view(), name='edituser'),
    path('update-profile', views.UpdateProfile.as_view(), name='update-profile'),

   
]
