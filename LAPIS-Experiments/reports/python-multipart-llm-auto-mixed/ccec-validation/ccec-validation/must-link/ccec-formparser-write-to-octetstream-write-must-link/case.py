class OctetStreamParser:
    def write(self, data):
        return len(data)

class FormParser:
    def __init__(self, content_type):
        if content_type == "application/octet-stream":
            self.parser = OctetStreamParser()
        else:
            self.parser = None

    def write(self, data):
        return self.parser.write(data)

def sample():
    parser = FormParser("application/octet-stream")
    return parser.write(b"payload")
