import json
import hmac
import hashlib
import asyncio
import logging
from typing import Callable, Optional
from quart import Quart, request, Response
from lark_oapi import Client as LarkClient
from astrbot.api import logger


class LarkWebhookClient:
    """飞书 Webhook 模式客户端，使用 Quart 作为 Web 服务器"""

    def __init__(
        self,
        lark_client: LarkClient,
        encrypt_key: str,
        verification_token: str,
        host: str = "0.0.0.0",
        port: int = 3000,
        path: str = "/lark/events",
        event_handler: Optional[Callable] = None,
    ):
        self.lark_client = lark_client
        self.encrypt_key = encrypt_key
        self.verification_token = verification_token
        self.host = host
        self.port = port
        self.path = path
        self.event_handler = event_handler

        self.app = Quart(__name__)
        self._setup_routes()

        # 禁用 Quart 的默认日志输出
        logging.getLogger("quart.app").setLevel(logging.WARNING)
        logging.getLogger("quart.serving").setLevel(logging.WARNING)

        self.shutdown_event = asyncio.Event()

    def _setup_routes(self):
        """设置路由"""

        @self.app.route(self.path, methods=["POST"])
        async def lark_events():
            """处理飞书事件"""
            try:
                # 获取请求体和头部
                body = await request.get_data()
                event_data = json.loads(body.decode("utf-8"))

                # 验证飞书请求签名
                timestamp = request.headers.get("X-Lark-Request-Timestamp")
                nonce = request.headers.get("X-Lark-Request-Nonce")
                signature = request.headers.get("X-Lark-Signature")
                
                # 如果配置了 encrypt_key，则需要解密
                if self.encrypt_key and "encrypt" in event_data:
                    try:
                        # 飞书加密事件解密
                        from lark_oapi import AESCipher
                        cipher = AESCipher(self.encrypt_key)
                        encrypted_data = event_data["encrypt"]
                        decrypted_data = cipher.decrypt_str(encrypted_data)
                        event_data = json.loads(decrypted_data)
                        logger.info("飞书加密事件解密成功")
                    except Exception as e:
                        logger.error(f"飞书事件解密失败: {e}")
                        return Response("Decryption failed", status=400)
                elif signature and self.verification_token:
                    # 使用 verification_token 验证签名
                    sig_basestring = f"{timestamp}\n{nonce}\n{body.decode('utf-8')}"
                    my_signature = hmac.new(
                        self.verification_token.encode("utf-8"),
                        sig_basestring.encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()
                    # 验证签名
                    if not hmac.compare_digest(my_signature, signature):
                        logger.warning("飞书请求签名验证失败")
                        return Response("Invalid signature", status=400)
                
                logger.info(f"收到飞书事件: {event_data}")

                # 处理 URL 验证事件
                if event_data.get("type") == "url_verification":
                    return {"challenge": event_data.get("challenge")}
                
                # 处理事件
                if self.event_handler:
                    await self.event_handler(event_data)

                return Response("", status=200)

            except Exception as e:
                logger.error(f"处理飞书事件时出错: {e}")
                return Response("Internal Server Error", status=500)

        @self.app.route("/health", methods=["GET"])
        async def health_check():
            """健康检查端点"""
            return {"status": "ok", "service": "lark-webhook"}

    async def start(self):
        """启动 Webhook 服务器"""
        logger.info(
            f"飞书 Webhook 服务器启动中，监听 {self.host}:{self.port}{self.path}..."
        )

        await self.app.run_task(
            host=self.host,
            port=self.port,
            debug=False,
            shutdown_trigger=self.shutdown_trigger,
        )

    async def shutdown_trigger(self):
        await self.shutdown_event.wait()

    async def stop(self):
        """停止 Webhook 服务器"""
        self.shutdown_event.set()
        logger.info("飞书 Webhook 服务器已停止")