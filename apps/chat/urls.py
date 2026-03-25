"""Chat URL configuration."""

from django.urls import path
from .views import ConversationViewSet, NestConversationView, ChattableContactsView

conversation_list = ConversationViewSet.as_view({"get": "list"})
conversation_dm = ConversationViewSet.as_view({"post": "create_dm"})
conversation_messages = ConversationViewSet.as_view({"get": "list_messages"})
conversation_read = ConversationViewSet.as_view({"post": "mark_read"})

urlpatterns = [
    path("conversations/", conversation_list, name="chat-conversations"),
    path("conversations/dm/", conversation_dm, name="chat-create-dm"),
    path("conversations/<uuid:pk>/messages/", conversation_messages, name="chat-messages"),
    path("conversations/<uuid:pk>/read/", conversation_read, name="chat-mark-read"),
    path("contacts/", ChattableContactsView.as_view(), name="chat-contacts"),
    path("nest/<uuid:nest_id>/conversation/", NestConversationView.as_view(), name="nest-conversation"),
]
