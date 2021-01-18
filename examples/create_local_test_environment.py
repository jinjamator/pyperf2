from pyperf2 import Server, Client
from time import sleep
from pprint import pformat


def on_data_callback(message, **kwargs):
    print(f"got message {pformat(message)} \n\n kwargs are {pformat(kwargs)}")
    print("----------------------------------------------------------------------")


receiver = Server()
sender = Client()

receiver.set_options(protocol="udp", server_ip="127.0.0.1", test_duration=12)
receiver.register_on_data_callback(
    on_data_callback, some_custom_parameter="some_custom_value"
)
receiver.start()


sender.set_options(protocol="udp", server_ip="127.0.0.1", test_duration=10)
sender.start()

while sender.status != "stopped":
    print(f"status sender: {sender.status}\nstatus receiver: {receiver.status}\n")
    print("do something usefull in the main thread -> sleeping for 1 second\n")
    sleep(1)
