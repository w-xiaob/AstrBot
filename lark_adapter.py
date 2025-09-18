import base64
import asyncio
import json
import re
import uuid
from typing import Optional
import astrbot.api.message_components as Comp

from astrbot.api.platform import (
    Platform,
    AstrBotMessage,
    MessageMember,
    MessageType,
    PlatformMetadata,
)
from astrbot.api.event import MessageChain
from astrbot.core.platform.astr_message_event import MessageSesion
from .lark_event import LarkMessageEvent
from .client import LarkWebhookClient
from ...register import register_platform_adapter
from astrbot import logger
import lark_oapi as lark
from lark_oapi.api.im.v1 import *


@register_platform_adapter("lark", "飞书机器人官方 API 适配器")
class LarkPlatformAdapter(Platform):
    def __init__(
        self, platform_config: dict, platform_settings: dict, event_queue: asyncio.Queue
    ) -> None:
        super().__init__(event_queue)

        self.config = platform_config

        self.unique_session = platform_settings["unique_session"]

        self.appid = platform_config["app_id"]
        self.appsecret = platform_config["app_secret"]
        self.domain = platform_config.get("domain", lark.FEISHU_DOMAIN)
        self.bot_name = platform_config.get("lark_bot_name", "astrbot")

        # 连接模式
        self.connection_mode = platform_config.get("lark_connection_mode", "socket")
        
        # Webhook 模式相关参数
        self.webhook_host = platform_config.get("lark_webhook_host", "0.0.0.0")
        self.webhook_port = platform_config.get("lark_webhook_port", 3000)
        self.webhook_path = platform_config.get("lark_webhook_path", "/lark/events")
        self.encrypt_key = platform_config.get("lark_encrypt_key", "")
        self.verification_token = platform_config.get("lark_verification_token", "")

        if not self.bot_name:
            logger.warning("未设置飞书机器人名称，@ 机器人可能得不到回复。")

        async def on_msg_event_recv(event: lark.im.v1.P2ImMessageReceiveV1):
            await self.convert_msg(event)

        def do_v2_msg_event(event: lark.im.v1.P2ImMessageReceiveV1):
            asyncio.create_task(on_msg_event_recv(event))

        self.event_handler = (
            lark.EventDispatcherHandler.builder("", "")
            .register_p2_im_message_receive_v1(do_v2_msg_event)
            .build()
        )

        self.client = lark.ws.Client(
            app_id=self.appid,
            app_secret=self.appsecret,
            log_level=lark.LogLevel.ERROR,
            domain=self.domain,
            event_handler=self.event_handler,
        )

        self.lark_api = (
            lark.Client.builder()
            .app_id(self.appid)
            .app_secret(self.appsecret)
            .domain(self.domain)
            .build()
        )

        # Webhook 客户端
        self.webhook_client: Optional[LarkWebhookClient] = None

    async def send_by_session(
        self, session: MessageSesion, message_chain: MessageChain
    ):
        res = await LarkMessageEvent._convert_to_lark(message_chain, self.lark_api)
        wrapped = {
            "zh_cn": {
                "title": "",
                "content": res,
            }
        }

        if session.message_type == MessageType.GROUP_MESSAGE:
            id_type = "chat_id"
            if "%" in session.session_id:
                session.session_id = session.session_id.split("%")[1]
        else:
            id_type = "open_id"

        request = (
            CreateMessageRequest.builder()
            .receive_id_type(id_type)
            .request_body(
                CreateMessageRequestBody.builder()
                .receive_id(session.session_id)
                .content(json.dumps(wrapped))
                .msg_type("post")
                .uuid(str(uuid.uuid4()))
                .build()
            )
            .build()
        )

        response = await self.lark_api.im.v1.message.acreate(request)

        if not response.success():
            logger.error(f"发送飞书消息失败({response.code}): {response.msg}")

        await super().send_by_session(session, message_chain)

    def meta(self) -> PlatformMetadata:
        return PlatformMetadata(
            name="lark",
            description="飞书机器人官方 API 适配器",
            id=self.config.get("id"),
        )

    async def convert_msg(self, event: lark.im.v1.P2ImMessageReceiveV1):
        message = event.event.message
        abm = AstrBotMessage()
        abm.timestamp = int(message.create_time) / 1000
        abm.message = []
        abm.type = (
            MessageType.GROUP_MESSAGE
            if message.chat_type == "group"
            else MessageType.FRIEND_MESSAGE
        )
        if message.chat_type == "group":
            abm.group_id = message.chat_id
        abm.self_id = self.bot_name
        abm.message_str = ""

        at_list = {}
        if message.mentions:
            for m in message.mentions:
                at_list[m.key] = Comp.At(qq=m.id.open_id, name=m.name)
                if m.name == self.bot_name:
                    abm.self_id = m.id.open_id

        content_json_b = json.loads(message.content)

        if message.message_type == "text":
            message_str_raw = content_json_b["text"]  # 带有 @ 的消息
            at_pattern = r"(@_user_\d+)"  # 可以根据需求修改正则
            # at_users = re.findall(at_pattern, message_str_raw)
            # 拆分文本，去掉AT符号部分
            parts = re.split(at_pattern, message_str_raw)
            for i in range(len(parts)):
                s = parts[i].strip()
                if not s:
                    continue
                if s in at_list:
                    abm.message.append(at_list[s])
                else:
                    abm.message.append(Comp.Plain(parts[i].strip()))
        elif message.message_type == "post":
            _ls = []

            content_ls = content_json_b.get("content", [])
            for comp in content_ls:
                if isinstance(comp, list):
                    _ls.extend(comp)
                elif isinstance(comp, dict):
                    _ls.append(comp)
            content_json_b = _ls
        elif message.message_type == "image":
            content_json_b = [
                {"tag": "img", "image_key": content_json_b["image_key"], "style": []}
            ]

        if message.message_type in ("post", "image"):
            for comp in content_json_b:
                if comp["tag"] == "at":
                    abm.message.append(at_list[comp["user_id"]])
                elif comp["tag"] == "text" and comp["text"].strip():
                    abm.message.append(Comp.Plain(comp["text"].strip()))
                elif comp["tag"] == "img":
                    image_key = comp["image_key"]
                    request = (
                        GetMessageResourceRequest.builder()
                        .message_id(message.message_id)
                        .file_key(image_key)
                        .type("image")
                        .build()
                    )
                    response = await self.lark_api.im.v1.message_resource.aget(request)
                    if not response.success():
                        logger.error(f"无法下载飞书图片: {image_key}")
                    image_bytes = response.file.read()
                    image_base64 = base64.b64encode(image_bytes).decode()
                    abm.message.append(Comp.Image.fromBase64(image_base64))

        for comp in abm.message:
            if isinstance(comp, Comp.Plain):
                abm.message_str += comp.text
        abm.message_id = message.message_id
        abm.raw_message = message
        abm.sender = MessageMember(
            user_id=event.event.sender.sender_id.open_id,
            nickname=event.event.sender.sender_id.open_id[:8],
        )
        # 独立会话
        if not self.unique_session:
            if abm.type == MessageType.GROUP_MESSAGE:
                abm.session_id = abm.group_id
            else:
                abm.session_id = abm.sender.user_id
        else:
            if abm.type == MessageType.GROUP_MESSAGE:
                abm.session_id = f"{abm.sender.user_id}%{abm.group_id}"  # 也保留群组id
            else:
                abm.session_id = abm.sender.user_id

        logger.debug(abm)
        await self.handle_msg(abm)

    async def handle_msg(self, abm: AstrBotMessage):
        event = LarkMessageEvent(
            message_str=abm.message_str,
            message_obj=abm,
            platform_meta=self.meta(),
            session_id=abm.session_id,
            bot=self.lark_api,
        )

        self._event_queue.put_nowait(event)

    async def run(self):
        if self.connection_mode == "socket":
            logger.info("使用 Socket 模式连接飞书...")
            await self.client._connect()
        elif self.connection_mode == "webhook":
            logger.info("使用 Webhook 模式连接飞书...")
            # 初始化 Webhook 客户端
            self.webhook_client = LarkWebhookClient(
                lark_client=self.client,
                encrypt_key=self.encrypt_key,
                verification_token=self.verification_token,
                host=self.webhook_host,
                port=self.webhook_port,
                path=self.webhook_path,
                event_handler=self._handle_webhook_event,
            )
            await self.webhook_client.start()
        else:
            raise ValueError(f"不支持的连接模式: {self.connection_mode}")

    async def terminate(self):
        """终止连接"""
        if self.connection_mode == "socket" and self.client:
            await self.client.stop()
        elif self.connection_mode == "webhook" and self.webhook_client:
            await self.webhook_client.stop()
        logger.info("飞书(Lark) 适配器已被优雅地关闭")

    def get_client(self) -> lark.Client:
        return self.client

    async def _handle_webhook_event(self, event_data: dict):
        """处理 Webhook 事件"""
        try:
            # 转换为 AstrBot 消息格式
            message = self._convert_lark_event_to_astrbot_message(event_data)
            
            # 如果是机器人自己发送的消息，忽略
            # 注意：这里应该比较机器人的 open_id 而不是名称
            # 由于在 Webhook 模式下难以获取机器人自己的 open_id，暂时注释掉这个检查
            # 如果需要实现此功能，应该通过飞书 API 获取机器人的身份信息进行比较
            
            # 发送到消息处理器
            await self.handle_msg(message)
        except Exception as e:
            logger.error(f"处理飞书 Webhook 事件时出错: {e}")
            
    def _convert_lark_event_to_astrbot_message(self, event: dict) -> AstrBotMessage:
        """将飞书事件转换为 AstrBot 消息格式"""
        message = AstrBotMessage()
        
        # 解析飞书webhook事件结构
        header = event.get("header", {})
        event_body = event.get("event", {})
        
        # 设置消息类型
        message_type = MessageType.GROUP_MESSAGE if event_body.get("message", {}).get("chat_type") == "group" else MessageType.FRIEND_MESSAGE
        message.type = message_type
        
        # 设置群组ID（如果是群聊）
        if message.type == MessageType.GROUP_MESSAGE:
            message.group_id = event_body.get("message", {}).get("chat_id", "")
        
        # 设置消息ID
        message.message_id = event_body.get("message", {}).get("message_id", str(uuid.uuid4()))
        
        # 设置发送者信息
        sender = event_body.get("sender", {})
        sender_id_info = sender.get("sender_id", {})
        user_id = sender_id_info.get("open_id", "")
        user_name = sender_id_info.get("user_name", user_id[:8] if user_id else "")
        
        message.sender = MessageMember(
            user_id=user_id,
            nickname=user_name
        )
        
        # 设置消息内容
        message.message = []
        message.message_str = ""
        
        # 解析消息内容
        message_content = event_body.get("message", {})
        content = message_content.get("content", "")
        
        # 构建@提及映射表
        at_list = {}
        mentions = event_body.get("message", {}).get("mentions", [])
        for m in mentions:
            key = m.get("key", "")
            open_id = m.get("id", {}).get("open_id", "")
            name = m.get("name", "")
            if key and open_id:
                at_list[key] = Comp.At(qq=open_id, name=name)
                if name == self.bot_name:
                    message.self_id = open_id
        
        # 根据飞书webhook事件格式，content字段是JSON字符串
        try:
            content_json = json.loads(content)
            # 处理文本消息
            if "text" in content_json:
                text = content_json["text"]
                message.message_str = text
                
                # 处理@提及消息（类似于convert_msg中的逻辑）
                at_pattern = r"(@_user_\d+)"  # 匹配@提及模式
                parts = re.split(at_pattern, text)
                for i in range(len(parts)):
                    s = parts[i].strip()
                    if not s:
                        continue
                    if s in at_list:
                        message.message.append(at_list[s])
                    else:
                        message.message.append(Comp.Plain(s))
            else:
                # 其他类型的消息，直接作为文本处理
                message.message_str = content
                message.message.append(Comp.Plain(content))
        except json.JSONDecodeError:
            # 如果不是JSON格式，直接作为文本处理
            message.message_str = content
            message.message.append(Comp.Plain(content))
            
        # 确保群聊消息中的指令前缀能够被正确识别
        # 飞书群聊消息可能包含额外的格式，需要确保message_str以指令前缀开头
        if (message.type == MessageType.GROUP_MESSAGE and 
            message.message_str):
            # 检查消息是否包含指令前缀但被其他内容包裹
            for wake_prefix in self.config.get("wake_prefix", ["/"]):
                if wake_prefix in message.message_str:
                    # 提取指令部分，确保指令前缀能够被唤醒检查阶段识别
                    prefix_index = message.message_str.find(wake_prefix)
                    if prefix_index >= 0:
                        # 保留原始消息内容，但确保指令前缀能够被识别
                        message.message_str = message.message_str[prefix_index:]
                        break
        
        # 设置会话ID（与convert_msg方法保持一致）
        if not self.unique_session:
            if message.type == MessageType.GROUP_MESSAGE:
                message.session_id = message.group_id
            else:
                message.session_id = message.sender.user_id
        else:
            if message.type == MessageType.GROUP_MESSAGE:
                message.session_id = f"{message.sender.user_id}%{message.group_id}"  # 也保留群组id
            else:
                message.session_id = message.sender.user_id
            
        return message
