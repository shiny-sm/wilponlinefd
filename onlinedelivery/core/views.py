from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from .models import User, Role, Permission
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated, IsAdminUser, IsAuthenticatedOrReadOnly


class UserRegistration(APIView):
    def post(self, request):
        data = request.data
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        roleid = data.get('roleid')

        if not username or not email or not password:
            return Response({'error': 'Username, email, and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username is already taken.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email is already registered.'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, email=email, password=password, roleid=Role.objects.get(pk=roleid))
        return Response({'message': 'User registered successfully.'}, status=status.HTTP_201_CREATED)
    
class UserLogin(APIView):
    def post(self, request):
        data = request.data
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return Response({'error': 'Username and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(username=username, password=password)
        if user is not None:
            # User is authenticated, return success response
            return Response({'message': 'Login successful.', 'user_id': user.id}, status=status.HTTP_200_OK)
        else:
            # Authentication failed, return error response
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

class UserLogout(APIView):  
    def post(self, request):
        if request.method == "POST":
            request.user.auth_token.delete()
            return Response({'Message': 'You are logged out.'}, status=status.HTTP_200_OK)


# class TokenGeneration(APIView):    
#     def post(self, request):
#         data = request.data
#         username = data.get('username')
#         password = data.get('password')

#         if not username or not password:
#             return Response({'error': 'Username and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

#         user = User.objects.filter(username=username).first()
#         if user is None or not user.check_password(password):
#             return Response({'error': 'Invalid username or password.'}, status=status.HTTP_401_UNAUTHORIZED)

#         token, created = Token.objects.get_or_create(user=user)
#         return Response({'token': token.key}, status=status.HTTP_200_OK)
    
class UserRoleManagement(APIView):
    permission_classes = [IsAdminUser]
    def post(self, request):
        data = request.data
        permission = data.get('permission')
        roleid = data.get('roleid')

        if not permission or not roleid:
            return Response({'error': 'ENter the role id and permission assigned to that role.'}, status=status.HTTP_400_BAD_REQUEST)

        # Assuming the user is already authenticated using TokenAuthentication
        # Get the user from the request
        if not request.user.is_superuser:
            return Response({'error': 'You do not have permission to manage roles.'}, status=status.HTTP_403_FORBIDDEN)

        # Create a new Role instance
        new_permission = Permission(name=permission,roleid=Role.objects.get(pk=roleid))
        
        new_permission.save()


        return Response({'message': 'Role permission done successfully.'}, status=status.HTTP_200_OK)
    
class UserPermission(APIView):
    def post(self, request):
        data = request.data
        username = data.get('username')
        actionallowed = data.get('action')
        if not username or not actionallowed:
            return Response({'error': 'Username and action are required.'}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(username=username).exists():   
            if request.user.is_authenticated:
                print(request.user.id)
                arrPermissions = Permission.objects.filter(roleid=Role.objects.get(pk=request.user.roleid.id))
                for permission in arrPermissions:
                    print(permission.name)
                    if permission.name == actionallowed:
                        return Response({'message': 'Permitted'}, status=status.HTTP_200_OK)

                return Response({'message': 'Not Permitted'}, status=status.HTTP_403_FORBIDDEN)
                # Your view logic here
                print("Authenticated user")

            # If session expired or user is not authenticated, handle accordingly
            else:
                print("Session expired or user not authenticated")
        else:
            return Response({'error': 'Username is not registered with us.'}, status=status.HTTP_400_BAD_REQUEST)