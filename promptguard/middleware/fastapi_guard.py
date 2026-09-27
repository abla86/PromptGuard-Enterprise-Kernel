import json
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from promptguard.core.engine import PromptGuardEngine
from promptguard.core.models import EnforcementAction


class PromptGuardMiddleware(BaseHTTPMiddleware):
    """FastAPI Middleware som automatisk skanner innkommende JSON-meldinger."""

    def __init__(self, app, engine: PromptGuardEngine = None):
        super().__init__(app)
        self.engine = engine or PromptGuardEngine()

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type:
                body = await request.body()
                if body:
                    try:
                        payload = json.loads(body.decode("utf-8"))
                        if isinstance(payload, dict):
                            for k, v in payload.items():
                                if isinstance(v, str):
                                    report = self.engine.inspect_and_contain(v)
                                    if report.action == EnforcementAction.BLOCK:
                                        return JSONResponse(
                                            status_code=400,
                                            content={
                                                "error": "PromptGuardSecurityException: Inbound Payload Blocked",
                                                "field": k,
                                                "violations": [
                                                    {
                                                        "category": viol.category.value,
                                                        "risk": viol.risk_score,
                                                        "desc": viol.description,
                                                    }
                                                    for viol in report.violations
                                                ],
                                            },
                                        )
                    except Exception:
                        pass

        return await call_next(request)
