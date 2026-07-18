def _make_method(name, doc):
    if name == "__array__":
        def __array__(self):
            return "pickle.loads boundary"
        return __array__
    return lambda self: None

def class_factory(methods):
    namespace = {}
    for name, doc in methods:
        namespace[name] = _make_method(name, doc)
    return type("Netref", (), namespace)

def sample():
    obj = class_factory([("__array__", "array protocol")])()
    other_callback = getattr(obj, "__array__")
    return other_callback()
