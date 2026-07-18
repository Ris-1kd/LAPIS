class CallbackDispatcher:
    def __init__(self, callbacks, content_type):
        self.callbacks = callbacks
        self.content_type = content_type

    def callback(self, name, data=None, start=None, end=None):
        if self.content_type != "application/octet-stream":
            return None
        func = self.callbacks.get("on_" + name)
        if data is None:
            return func()
        return func(data, start, end)

def on_start(*args):
    return "callback"

def sample():
    dispatcher = CallbackDispatcher({"on_start": on_start}, "multipart/form-data")
    data = b"payload"
    return dispatcher.callback("start")
