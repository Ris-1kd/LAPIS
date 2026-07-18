class FormParser:
    def __init__(self, content_type):
        self.parser = None

    def write(self, data):
        if self.parser is None:
            return None
        return self.parser.write(data)

def sample():
    parser = FormParser("multipart/form-data")
    return parser.write(b"payload")
