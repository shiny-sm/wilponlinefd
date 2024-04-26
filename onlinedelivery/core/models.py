from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.

class Role(models.Model):
    name = models.CharField(max_length=100)

class User(AbstractUser):
    # Add custom fields as needed
    roleid = models.ForeignKey(Role, on_delete=models.CASCADE)


class Permission(models.Model):
    name = models.CharField(max_length=100)
    roleid = models.ForeignKey(Role, on_delete=models.CASCADE)

# class UserRole(models.Model):
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     role = models.ForeignKey(Role, on_delete=models.CASCADE)
#     permissions = models.ManyToManyField(Permission)

# class Token(models.Model):
#     user = models.OneToOneField(User, on_delete=models.CASCADE)
#     token = models.CharField(max_length=40, unique=True)
