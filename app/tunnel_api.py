"""Owner-only automatic tunnel pairing, preview and durable worker jobs."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from starlette.responses import JSONResponse
from pydantic import ValidationError

from .db import audit, database
from .deps import owner
from .tunnel_bridge import (
    BridgeError,
    Connection,
    ConnectionInput,
    Job,
    PairInput,
    Preview,
    PreviewInput,
    Profile,
    StartInput,
    State,
    SUPPORTED,
    TunnelClient,
    enabled,
)


def call(method, route, body=None):
    if not enabled():
        raise HTTPException(503, "اتصال Donino Tunnel روی این میزبان فعال نشده است")
    try:
        return TunnelClient().request(method, route, body)
    except BridgeError as error:
        raise HTTPException(
            error.status,
            "کنترل‌کنندهٔ تانل پاسخ معتبر نداد؛ وضعیت عملیات را بررسی کنید و پیش از بررسی، درخواست را تکرار نکنید",
        ) from None


def public(model, value):
    try:
        return model.model_validate(value).model_dump()
    except ValidationError:
        raise HTTPException(502, "نسخه یا پاسخ کنترل‌کنندهٔ تانل ناسازگار است") from None


def record(account, action, target):
    with database() as db:
        audit(db, account["username"], "tunnel." + action, target)


class PrivateValidationRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def safe(request):
            try:
                return await handler(request)
            except RequestValidationError:
                return JSONResponse(
                    {"detail": "دادهٔ درخواست تانل معتبر نیست"}, status_code=422
                )

        return safe


def mount_tunnel_api(app):
    router = APIRouter(route_class=PrivateValidationRoute)

    @router.get("/api/tunnels/state")
    def state(account=Depends(owner)):
        if not enabled():
            return {
                "enabled": False,
                "available": False,
                "reason": "Donino Tunnel باید روی میزبان پنل با نقش ایران نصب و اتصال محلی فعال شود.",
            }
        try:
            result = public(State, call("GET", "/state"))
        except HTTPException as error:
            if error.status_code == 503:
                return {
                    "enabled": True,
                    "available": False,
                    "reason": "سرویس محلی یا مجوز socket در دسترس نیست؛ راهنمای اتصال تانل را بررسی کنید.",
                }
            raise
        return {**result, "enabled": True, "supported_transports": list(SUPPORTED)}

    @router.post("/api/tunnels/pair", status_code=201)
    def pair(body: PairInput, account=Depends(owner)):
        result = public(Profile, call("POST", "/pair", body.model_dump()))
        record(account, "pair", result["id"])
        return result

    @router.post("/api/tunnels/connection")
    def connection(body: ConnectionInput, account=Depends(owner)):
        return public(Connection, call("POST", "/connection", body.model_dump()))

    @router.post("/api/tunnels/preview", status_code=201)
    def preview(body: PreviewInput, account=Depends(owner)):
        result = public(Preview, call("POST", "/preview", body.worker_spec()))
        record(account, "preview", result["id"])
        return result

    @router.post("/api/tunnels/start", status_code=202)
    def start(body: StartInput, account=Depends(owner)):
        result = public(Job, call("POST", "/start", body.model_dump()))
        record(account, "start", result["id"])
        return result

    app.include_router(router)
