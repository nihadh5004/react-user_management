from django.shortcuts import render
from django.http import JsonResponse
# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from .serializers import *
from django.http import FileResponse
class SignupView(APIView):  # Correct the class name to SignupView
    def post(self, request):
        # Your registration logic here
        user_serializer=UserSerializer(data=request.data)
        if user_serializer.is_valid():
            user = User.objects.create_user(
                username=user_serializer.validated_data['username'],
                email=user_serializer.validated_data['email'],
                password=user_serializer.validated_data['password']
            )
            return Response({'message': 'User registered successfully.'}, status=status.HTTP_201_CREATED)
        else:
            return Response(user.errors, status=status.HTTP_400_BAD_REQUEST)
       
class HomeView(APIView):
     
    permission_classes = (IsAuthenticated, )
    def get(self, request):
        content = {'message': 'Welcome to the JWT Authentication page using React Js and Django!'}
        return Response(content)
    
    
class Signout(APIView):
     # permission_classes = (IsAuthenticated, )
     def post(self, request):
          refresh_token = request.data.get('refresh_token')
          print(refresh_token)
          if refresh_token:
               try:
                    print('no')
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                    print('no')
                    response = JsonResponse({"message": "Logged out successfully."})
                
                    return response
               except:
                    return Response({'error': 'Invalid refresh token.'}, status=status.HTTP_400_BAD_REQUEST)
          else:
               return Response({'error': 'Refresh token not provided.'}, status=status.HTTP_400_BAD_REQUEST)



from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import CustomTokenObtainPairSerializer

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class ProfileView(APIView):
#     authentication_classes = [JWTAuthentication]  # Use JWTAuthentication
     permission_classes = [IsAuthenticated]  # Require authentication
     def get(self, request):
          username = request.query_params.get('username')
          try:
               user = User.objects.get(username=username)
               user_serializer = UserSerializer(user)

               # Check if there is a profile entry for the user
               try:
                    profile = Profile.objects.get(user=user)
                    profile_serializer = ProfileSerializer(profile)

                    # Include the profile image URL in the response
                    response_data = {
                         'user': user_serializer.data,
                         'profile': profile_serializer.data,
                    }

                    return Response(response_data, status=status.HTTP_200_OK)
               except Profile.DoesNotExist:
                    response_data = {
                         'user': user_serializer.data,
                         'profile': '',
                    }

                    return Response(response_data, status=status.HTTP_200_OK)
          except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
       
       
class UserList(APIView):
#     authentication_classes = [JWTAuthentication]  # Use JWTAuthentication
    permission_classes = [IsAuthenticated]  # Require authentication
    def get(self, request):
          userId = request.query_params.get('userId')
          print(userId)
          user = User.objects.get(id = userId)
          if user.is_superuser:
               users = User.objects.all()
               serializer = UserListSerializer(users, many=True)  # Serialize the list of users
               return Response(serializer.data, status=status.HTTP_200_OK)
          else:
               return Response( {'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
     
     
class AddUser(APIView):
     permission_classes = [IsAuthenticated]  # Require authentication

     def post(self,request):
          user_serializer=UserSerializer(data=request.data)
          if user_serializer.is_valid():
               user = User.objects.create_user(
                    username=user_serializer.validated_data['username'],
                    email=user_serializer.validated_data['email'],
                    password=user_serializer.validated_data['password']
               )
               response_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_active': user.is_active,
                'is_superuser': user.is_superuser
               }
               # users=User.objects.all()
               # serializer = UserListSerializer(users, many=True)  # Serialize the list of users
               # return Response({'message': 'User registered successfully.'},serializer.data, status=status.HTTP_201_CREATED)
               return Response({'message': 'User registered successfully.', 'user': response_data}, status=status.HTTP_201_CREATED)
          else:
               return Response( status=status.HTTP_400_BAD_REQUEST)
          
          
class DeleteUser(APIView):
     permission_classes = [IsAuthenticated]  # Require authentication

     def post(self,request):
          userId=request.data.get('userId')
          print(userId)
          
          try:
               user=User.objects.get(id=userId)
               user.delete()
               users=User.objects.all()
               
               serializer = UserListSerializer(users, many=True)  # Serialize the list of users
               return Response(serializer.data, status=status.HTTP_200_OK)
          except:
               return Response( status=status.HTTP_400_BAD_REQUEST)
          
          
class EditUser(APIView):
     permission_classes = [IsAuthenticated]  # Require authentication

     def post(self, request):
          user_serializer = EditUserSerializer(data=request.data)
          print('hello')
          if user_serializer.is_valid():
               print('hello')

               user_id = user_serializer.validated_data['id']
               print(user_id)

               try:
                    print(user_id)
                    user = User.objects.get(pk=user_id)
                    print(user)
                    user.username = user_serializer.validated_data['username']
                    user.email = user_serializer.validated_data['email']
                    password = user_serializer.validated_data.get('password', None)


                    if password :
                         user.set_password(password)
                    #   user.password = user_serializer.validated_data['password']
                    user.save()
                    print('hello')
                    
                    users=User.objects.all()
                         
                    serializer = UserListSerializer(users, many=True)  # Serialize the list of users
                    return Response(serializer.data, status=status.HTTP_200_OK)
               except:
                    return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
          else:
               print(user_serializer.errors)  # Print the errors
               return Response(status=status.HTTP_400_BAD_REQUEST)
          
class UpdateProfile(APIView):
     permission_classes = [IsAuthenticated]  # Require authentication

     def post(self, request, *args, **kwargs):
          try:
               # Assuming the image is passed as 'image' in the request files
               image = request.FILES['image']
               username = request.query_params.get('username')
               print(username)
               user =User.objects.get(username=username)
               # Assuming you have a UserProfile model for user profiles
               
               user_profile, created = Profile.objects.get_or_create(user=user)
     
               # Update the profile image
               user_profile.profile_image = image
               user_profile.save()
               
               # Serialize the updated user profile and return it
               serializer = ProfileSerializer(user_profile)
               
               return Response(serializer.data, status=status.HTTP_200_OK)
          except Exception as e:
               return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)