# urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'rooms', views.RoomViewSet, basename='room')
router.register(r'interviews', views.InterviewViewSet, basename='interview')

urlpatterns = [
    path('', include(router.urls)),
]