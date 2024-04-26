from django.urls import path
#from .views import UserRegistration, UserLogin, TokenGeneration, UserRoleManagement
from core.views import UserRegistration, UserLogin, UserRoleManagement, UserLogout,UserPermission
from rest_framework.authtoken.views import obtain_auth_token
urlpatterns = [
    path('register/', UserRegistration.as_view(), name='user_registration'),
    path('login/', obtain_auth_token, name='login'),
    path('logout/', UserLogout.as_view(), name='logout'),
    # //path('generate-token/', TokenGeneration.as_view(), name='generate_token'),
    path('manage-role/', UserRoleManagement.as_view(), name='manage_role'),
    path('ispermitted/',UserPermission.as_view(), name='ispermitted'),
    # Other endpoints...
]