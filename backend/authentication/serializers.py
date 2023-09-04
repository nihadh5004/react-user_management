from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user
        data['is_superuser'] = user.is_superuser
        data['id']=user.id
        return data


from rest_framework import serializers
from django.contrib.auth.models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'password')  

        

        

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)
    
class UserListSerializer(serializers.ModelSerializer):
    # specify model and fields
    class Meta:
        model = User
        fields = ('id','username','email', 'is_active','is_superuser')
        
class EditUserSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    username = serializers.CharField(max_length=150)
    email = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True, required=False)  
    
    
from .models import Profile
class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['profile_image']