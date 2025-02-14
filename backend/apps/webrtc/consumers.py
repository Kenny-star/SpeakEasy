# consumers.py
from channels.generic.websocket import JsonWebsocketConsumer
from channels.db import database_sync_to_async
from django.core.exceptions import ObjectDoesNotExist
import json
import logging

logger = logging.getLogger(__name__)

class RoomConsumer(JsonWebsocketConsumer):
    async def connect(self):
        self.user = self.scope["user"]
        self.room_id = self.scope["url_route"]["kwargs"]["room_id"]
        
        try:
            self.room = await self._get_room()
            self.participant = await self._get_participant()
            
            await self.channel_layer.group_add(
                f"room_{self.room_id}",
                self.channel_name
            )
            
            await self.accept()
            
            # Notify others about new participant
            await self._notify_participant_joined()
            
        except ObjectDoesNotExist:
            await self.close()
        except Exception as e:
            logger.error(f"WebSocket connection error: {str(e)}")
            await self.close()

    async def disconnect(self, close_code):
        try:
            await self._notify_participant_left()
            await self.channel_layer.group_discard(
                f"room_{self.room_id}",
                self.channel_name
            )
        except Exception as e:
            logger.error(f"WebSocket disconnection error: {str(e)}")

    async def receive_json(self, content):
        message_type = content.get('type')
        
        try:
            if message_type == 'offer':
                await self._handle_offer(content)
            elif message_type == 'answer':
                await self._handle_answer(content)
            elif message_type == 'ice-candidate':
                await self._handle_ice_candidate(content)
            else:
                logger.warning(f"Unknown message type: {message_type}")
                
        except Exception as e:
            logger.error(f"Error handling message: {str(e)}")
            await self.send_json({
                'type': 'error',
                'message': 'Failed to process message'
            })

    @database_sync_to_async
    def _get_room(self):
        return Room.objects.get(id=self.room_id)

    @database_sync_to_async
    def _get_participant(self):
        return Participant.objects.get(
            room_id=self.room_id,
            user=self.user
        )