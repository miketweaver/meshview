import asyncio
import random
import aiomqtt
from google.protobuf.message import DecodeError
from meshtastic.protobuf.mqtt_pb2 import ServiceEnvelope
from meshview.key_manager import decrypt_packet, initialize_key_manager
from meshview.config import CHANNEL_KEYS

# Initialize the key manager with keys from config
initialize_key_manager(CHANNEL_KEYS)


def decrypt(packet):
    """Decrypt a packet using the multi-key system."""
    decrypt_packet(packet)


async def get_topic_envelopes(mqtt_server, mqtt_port, topics, mqtt_user, mqtt_passwd):
    identifier = str(random.getrandbits(16))
    while True:
        try:
            async with aiomqtt.Client(
                mqtt_server,
                port=mqtt_port,
                username=mqtt_user,
                password=mqtt_passwd,
                identifier=identifier,
            ) as client:
                for topic in topics:
                    print(f"Subscribing to: {topic}")
                    await client.subscribe(topic)

                async for msg in client.messages:
                    try:
                        envelope = ServiceEnvelope.FromString(msg.payload)
                    except DecodeError:
                        continue

                    decrypt(envelope.packet)
                    if not envelope.packet.decoded:
                        continue

                    # Skip packets from specific node
                    if getattr(envelope.packet, "from", None) == 2144342101:
                        continue

                    yield msg.topic.value, envelope

        except aiomqtt.MqttError as e:
            print(f"MQTT error: {e}, reconnecting in 1s...")
            await asyncio.sleep(1)
