"""
@文件        :__init__.py
@说明        :This is an example
@时间        :2025/06/30 09:17:23
@作者        :xxx
@邮箱        :
@版本        :1.0.0
"""

import json

from simplejrpc.interfaces import RPCMiddleware

from app.utils.logger import logger


class ExampleMiddleware(RPCMiddleware):
    """ """

    def process_request(self, request, context):
        # print("[middleware-request] ", request, context)

        if "ping" not in str(request):
            if isinstance(request, tuple):
                _req = json.loads(request[0])
                method = _req["method"]
                params = _req["params"]
                logger.info(f"\033[92m[API] {method} {params}\033[0m")
            else:
                logger.info(f"\033[92m[API] {request}\033[0m")

        return request

    def process_response(self, response, context):
        # print("[middleware-response] ", response, context)
        return response
