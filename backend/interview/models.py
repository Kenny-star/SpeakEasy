# models.py
from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
import uuid

class BaseModel(models.Model):
    """Base model with common fields"""
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True

class Room(BaseModel):
    """Video conference room model"""
    STATUS_CHOICES = [
        ('waiting', 'Waiting'),
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled')
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='waiting')
    name = models.CharField(max_length=255)
    max_participants = models.PositiveIntegerField(default=2)
    is_recorded = models.BooleanField(default=False)
    recording_consent = models.BooleanField(default=False)

    def clean(self):
        if self.is_recorded and not self.recording_consent:
            raise ValidationError("Recording consent is required for recorded rooms")

    class Meta:
        ordering = ['-created_at']

class Interview(BaseModel):
    """Interview session model"""
    STATUS_CHOICES = [
        ('scheduled', 'Scheduled'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
        ('no_show', 'No Show')
    ]
    
    room = models.OneToOneField(Room, on_delete=models.CASCADE)
    interviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='conducted_interviews'
    )
    candidate = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='interviews'
    )
    scheduled_at = models.DateTimeField()
    duration = models.DurationField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='scheduled')
    position = models.CharField(max_length=255)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ['-scheduled_at']
        permissions = [
            ("can_conduct_interview", "Can conduct interviews"),
            ("can_view_all_interviews", "Can view all interviews")
        ]

class Participant(BaseModel):
    """Room participant model"""
    room = models.ForeignKey(Room, on_delete=models.CASCADE, related_name='participants')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=[
        ('host', 'Host'),
        ('participant', 'Participant')
    ])
    joined_at = models.DateTimeField(null=True, blank=True)
    left_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ['room', 'user']

class Feedback(BaseModel):
    """Interview feedback model"""
    interview = models.ForeignKey(Interview, on_delete=models.CASCADE, related_name='feedbacks')
    evaluator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    technical_rating = models.PositiveSmallIntegerField(choices=[(i, i) for i in range(1, 6)])
    communication_rating = models.PositiveSmallIntegerField(choices=[(i, i) for i in range(1, 6)])
    problem_solving_rating = models.PositiveSmallIntegerField(choices=[(i, i) for i in range(1, 6)])
    cultural_fit_rating = models.PositiveSmallIntegerField(choices=[(i, i) for i in range(1, 6)])
    strengths = models.TextField()
    areas_for_improvement = models.TextField()
    recommendation = models.CharField(max_length=20, choices=[
        ('strong_yes', 'Strong Yes'),
        ('yes', 'Yes'),
        ('maybe', 'Maybe'),
        ('no', 'No'),
        ('strong_no', 'Strong No')
    ])
    final_notes = models.TextField(blank=True)

    class Meta:
        unique_together = ['interview', 'evaluator']