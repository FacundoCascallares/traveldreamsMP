from django.contrib.auth.models import Group
from django.dispatch import receiver
from django.db.models.signals import post_save
from django.contrib.auth.models import User
from .models import Profile

@receiver(post_save, sender=Profile)
def add_user_to_usuarios_group(sender, instance, created, **kwargs):
    if created:
        try:
            usuarios = Group.objects.get(name='usuario')
        except Group.DoesNotExist:
            usuarios = Group.objects.create(name='usuario')
            usuarios = Group.objects.create(name='administradores')
            usuarios = Group.objects.create(name='desarrolladores')
        instance.user.groups.add(usuarios)    

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()