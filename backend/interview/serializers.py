# serializers.py
from rest_framework import serializers
from django.utils import timezone
from .models import Room, Interview, Participant, Feedback

class RoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = Room
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')

    def validate(self, data):
        if data.get('is_recorded') and not data.get('recording_consent'):
            raise serializers.ValidationError({
                'recording_consent': 'Recording consent is required for recorded rooms'
            })
        return data

class InterviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Interview
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at')

    def validate_scheduled_at(self, value):
        if value < timezone.now():
            raise serializers.ValidationError("Cannot schedule interviews in the past")
        return value

    def validate(self, data):
        if data.get('status') == 'completed' and not data.get('notes'):
            raise serializers.ValidationError({
                'notes': 'Notes are required when marking interview as completed'
            })
        return data

class ParticipantSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source='user.email', read_only=True)
    
    class Meta:
        model = Participant
        fields = '__all__'
        read_only_fields = ('joined_at', 'left_at')

class FeedbackSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feedback
        fields = '__all__'
        read_only_fields = ('evaluator',)

    def validate(self, data):
        if data.get('recommendation') in ['strong_yes', 'yes'] and not data.get('strengths'):
            raise serializers.ValidationError({
                'strengths': 'Strengths must be provided for positive recommendations'
            })
        return data