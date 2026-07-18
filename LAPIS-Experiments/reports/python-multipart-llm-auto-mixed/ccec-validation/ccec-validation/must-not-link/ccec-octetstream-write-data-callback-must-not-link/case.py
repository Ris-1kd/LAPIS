class CallbackDispatcher:
    def __init__(self, callbacks):
        self.callbacks = callbacks

    def callback(self, name, data=None, start=None, end=None):
        func = self.callbacks.get("on_" + name)
        if func is None:
            return None
        if data is None:
            return func()
        return func(data, start, end)

def on_other():
    return "unrelated"

def sample():
    dispatcher = CallbackDispatcher({"on_other": on_other})
    data = b"payload"
    return dispatcher.callback("data", data, 0, len(data))
