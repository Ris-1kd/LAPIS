class OtherParser:
    def write(self, data):
        return 0

class FormParser:
    def __init__(self, content_type):
        self.parser = OtherParser()

    def write(self, data):
        return self.parser.write(data)

def sample():
    parser = FormParser("multipart/form-data")
    return parser.write(b"payload")
