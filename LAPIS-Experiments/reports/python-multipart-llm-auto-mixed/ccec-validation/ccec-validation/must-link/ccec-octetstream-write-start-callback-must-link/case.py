class CallbackDispatcher:
    def __init__(self, callbacks):
        self.callbacks = callbacks

    def callback(self, name, data=None, start=None, end=None):
        func = self.callbacks.get("on_" + name)
        if data is None:
            return func()
        return func(data, start, end)

def on_start():
    return "file-created"

def on_data(data, start, end):
    return data[start:end]

def sample():
    dispatcher = CallbackDispatcher({"on_start": on_start})
    data = b"payload"
    return dispatcher.callback("start")
