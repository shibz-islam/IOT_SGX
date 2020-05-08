import paho.mqtt.client as mqtt


def print_error_msg(rc):
    if rc != mqtt.MQTT_ERR_SUCCESS:
        mqtt.error_string(rc)


class MQTTClient:
    def __init__(self, host, port, keepalive, loop_forever=False):
        self.client = mqtt.Client()
        self.host = host
        self.port = port
        self.keep_alive = keepalive
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.client.on_subscribe = self.on_subscribe
        self.client.on_disconnect = self.on_disconnect
        self.client.connect(self.host, self.port, self.keep_alive)

    def run(self, forever=False):
        if forever:
            self.client.loop_forever()
        else:
            self.client.loop_start()


    ### callback functions
    def on_connect(self, client, userdata, flags, rc):
        print_error_msg(rc)

    def on_disconnect(self, client, userdata, rc):
        print_error_msg(rc)

    def on_subscribe(sefl, client, userdata, mid):
        print("Subscription to Topic successful!")

    def on_message(self, client, userdata, msg):
        print("#Topic: ", msg.topic)
        print("@Got msg: ", msg.payload.decode())

    def set_on_message_callback(self, func):
        self.client.on_message = func


    ### methods
    def subscribe(self, topic_name):
        (result, mid) = self.client.subscribe(topic_name)

    def disconnect(self):
        self.client.disconnect()

    def publish(self, topic_name, msg):
        info = self.client.publish(topic=topic_name, payload=msg)
        print_error_msg(info.rc)

    def stop_thread(self):
        self.client.loop_stop()

