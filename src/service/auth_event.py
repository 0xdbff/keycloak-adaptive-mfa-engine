from src.core.redis import get_redis
from src.data.schema import WebhookPayload

from src.utils.synchronization import synchronize_with_distributed_mutex
from src.utils.auth.dependency import tenant_scoped_id

from src.data.repository import AuthEventRepository, AuthProcessRepository
from src.data.model import AuthEvent, AuthProcess

from src.data.factory import AuthEventFactory

from time import time
from datetime import timedelta

import logging

import asyncio


class AuthEventService:

    def __init__(self, payload: WebhookPayload, realm: str):
        self.request_payload = payload
        self.redis = get_redis()
        self._user = payload.data.user_id
        # The realm that SIGNED this event (VerifiedPrincipal.realm), never a
        # value taken from the payload/claims — those are attacker-shapeable
        # content (see finding: Missing Tenant and Subject Binding on the
        # Login Event Webhook). This is what every per-user Redis key below is
        # namespaced by, so one realm's webhook traffic can never collide with
        # another realm's pending/counted state for the same user_id.
        self._realm = realm

    async def __call__(self):
        await self.process_auth_event()

    async def process_auth_event(self):
        @self.__synchronize_user_requests()
        async def __safe_call():
            return await self.__process_auth_event()

        result = await __safe_call()
        return result

    def __synchronize_user_requests(
        self,
    ):
        return (
            synchronize_with_distributed_mutex(
                lock_id=tenant_scoped_id(self._realm, self._user),
                prefix="lock_user",
            )
            if self._user is not None
            else (lambda _fn: _fn)
        )

    async def __process_auth_event(self):

        auth_event = await AuthEventFactory.partial_from_request(
            self.request_payload, realm=self._realm
        )
        event_type = str(self.request_payload.event_type)
        user_id = self.request_payload.data.user_id
        process_id = None

        logging.info(f"{self.request_payload}")
        logging.info(f"{self.request_payload.event_type}")

        if user_id:
            process_id = await self.__get_open_auth_process(user_id)

            if process_id is None:
                # No risk decision opened a process for this user in the last
                # 5 minutes: the attempt outlasted that window or bypassed the
                # check. The event is still stored, unlinked, so monitoring
                # sees it; there is no process to finalize.
                logging.info(
                    "No authentication process open for this user; storing the "
                    "%s event without a risk decision.",
                    event_type,
                )

            logging.debug(f"Using open auth process {process_id} for user {user_id}")
            auth_event.auth_process = process_id

        await self.__update_redis_cache(event_type=event_type, user_id=user_id)

        await AuthEventRepository.create_auth_event(auth_event)

        is_final_event = str(auth_event.event_type) in ("LOGIN", "LOGIN_ERROR")
        if process_id is not None and is_final_event:
            await self.__finalize_process(user_id, process_id, event_type)

    async def __update_redis_cache(self, event_type: str, user_id: str):
        _time = time()
        scoped_user = tenant_scoped_id(self._realm, user_id)

        tasks = [
            self.redis.set(
                name=f"d:{event_type}:{scoped_user}:{_time}",
                value=_time,
                ex=timedelta(days=1),
            ),
            self.redis.set(
                name=f"w:{event_type}:{scoped_user}:{_time}",
                value=_time,
                ex=timedelta(days=7),
            ),
            self.redis.set(
                name=f"m:{event_type}:{scoped_user}:{_time}",
                value=_time,
                ex=timedelta(days=31),
            ),
        ]

        await asyncio.gather(*tasks)

    async def __delete_redis_cache(self, user_id: str):
        await self.redis.delete(f"auth_process:{tenant_scoped_id(self._realm, user_id)}")

    async def __get_open_auth_process(self, user_id: str) -> str | None:
        return await self.redis.get(
            f"auth_process:{tenant_scoped_id(self._realm, user_id)}"
        )

    async def __finalize_process(
        self, user_id: str, process_id: str, final_status: str
    ):

        auth_process = await AuthProcessRepository.get_auth_process_by_id(
            process_id, realm_id=self._realm
        )

        if auth_process is None:
            raise ValueError(
                "Authentication process does not exist, cannot update final authentication status"
            )

        auth_process.final_status = final_status

        _ = await AuthProcessRepository.update_auth_process(auth_process)
        await self.__delete_redis_cache(user_id)
        logging.info(f"Auth process has been updated! id: {process_id}")
