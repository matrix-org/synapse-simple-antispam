import logging
import re
import yaml

logger = logging.getLogger(__name__)

class SimpleAntiSpam:
    def __init__(self, config):
        self.rules_file = config["rules_file"]
        self._reload_config()

        try:
            from synapse.app._base import register_sighup
            register_sighup(self._reload_config)
        except Exception:
            logger.warning(
                "Failed to install sighup handler for anti spam rule reloading"
            )

    def _reload_config(self, *args):
        with open(self.rules_file) as f:
            spam_config = yaml.safe_load(f)

            self._blocked_messages_by_homeserver = spam_config.get("blocked_messages_by_homeserver", [])
            self._blocked_messages_by_user = spam_config.get("blocked_messages_by_user", [])
            self._blocked_messages_by_content = spam_config.get("blocked_messages_by_content", [])

            self._blocked_messages_by_user_pattern = [re.compile(v) for v in spam_config.get("blocked_messages_by_user_pattern", [])]
            self._blocked_messages_by_content_pattern = [re.compile(v) for v in spam_config.get("blocked_messages_by_content_pattern", [])]

            self._blocked_invites_by_homeserver = spam_config.get("blocked_invites_by_homeserver", [])

    def check_event_for_spam(self, event):
        for bad_hs in self._blocked_messages_by_homeserver:
            if event.sender.endswith(":" + bad_hs):
                logger.info("Soft-failing event %s from %s", event.event_id,bad_hs)
                event.internal_metadata.soft_failed = True
                return True # not allowed (spam)

        for bad_user in self._blocked_messages_by_user:
            if event.sender == bad_user:
                return True # not allowed (spam)

        for bad_user in self._blocked_messages_by_user_pattern:
            if bad_user.search(event.sender):
                return True # not allowed (spam)

        for msg in self._blocked_messages_by_content:
            if event.content.get("body", "") == msg:
                return True # not allowed (spam)

        for msg in self._blocked_messages_by_content_pattern:
            if msg.search(event.content.get("body", "")):
                return True # not allowed (spam)

        return False # not spam

    def user_may_invite(self, inviter_user_id, invitee_user_id, room_id):
        for bad_hs in self.blocked_invites_by_homeserver:
            if inviter_user_id.endswith(":" + bad_hs):
                return False # not allowed

        return True # allowed

    def user_may_create_room(self, user_id):
        return True # allowed

    def user_may_create_room_alias(self, user_id, room_alias):
        return True # allowed

    def user_may_publish_room(self, user_id, room_id):
        return True # allowed

    @staticmethod
    def parse_config(config):
        return config # no parsing needed
