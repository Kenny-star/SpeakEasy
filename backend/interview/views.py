# views.py
from rest_framework import viewsets, status, mixins
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.core.exceptions import ValidationError
from django.db import transaction
from .models import Room, Interview, Participant, Feedback
from .serializers import (
    RoomSerializer, InterviewSerializer,
    ParticipantSerializer, FeedbackSerializer
)
from .permissions import IsInterviewer, CanViewAllInterviews

class RoomViewSet(viewsets.ModelViewSet):
    serializer_class = RoomSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        return Room.objects.filter(participants__user=user)

    @action(detail=True, methods=['post'])
    def join(self, request, pk=None):
        room = self.get_object()
        
        try:
            with transaction.atomic():
                participant, created = Participant.objects.get_or_create(
                    room=room,
                    user=request.user,
                    defaults={'role': 'participant'}
                )
                if not created:
                    participant.joined_at = timezone.now()
                    participant.save()
                
                return Response({
                    'room_id': str(room.id),
                    'ice_servers': settings.ICE_SERVERS,
                    'turn_credentials': self._get_turn_credentials()
                })
        except ValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['post'])
    def leave(self, request, pk=None):
        room = self.get_object()
        participant = room.participants.get(user=request.user)
        participant.left_at = timezone.now()
        participant.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

class InterviewViewSet(viewsets.ModelViewSet):
    serializer_class = InterviewSerializer
    permission_classes = [IsAuthenticated, IsInterviewer]

    def get_queryset(self):
        user = self.request.user
        if user.has_perm('interviews.can_view_all_interviews'):
            return Interview.objects.all()
        return Interview.objects.filter(interviewer=user)

    def perform_create(self, serializer):
        with transaction.atomic():
            room = Room.objects.create(
                name=f"Interview - {serializer.validated_data['position']}",
                max_participants=2
            )
            serializer.save(room=room, interviewer=self.request.user)

    @action(detail=True, methods=['post'])
    def complete(self, request, pk=None):
        interview = self.get_object()
        interview.status = 'completed'
        interview.save()
        
        # Send email notifications
        self._send_completion_notifications(interview)
        
        return Response({'status': 'completed'})