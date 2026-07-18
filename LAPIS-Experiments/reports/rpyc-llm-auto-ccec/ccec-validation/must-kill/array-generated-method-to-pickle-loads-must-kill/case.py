class PickleLike:
    def loads(self, value):
        return value

pickle = PickleLike()

def generated_str(self):
    return pickle.loads("payload")

def sample():
    return generated_str(object())
