import os

# Local attacker-controlled source stub
def cve_2026_24486_source():
    return "../../neutralized_by_guard.txt"

class File:
    def __init__(self, file_name=None, field_name=None, config=None):
        if file_name is not None:
            base, ext = os.path.splitext(file_name)
            self._file_base = base
            self._ext = ext
        else:
            self._file_base = "tmp"
            self._ext = ".bin"

    def save(self, file_dir, keep_filename=True, keep_extensions=True):
        if file_dir is not None and keep_filename:
            fname = self._file_base + self._ext if keep_extensions else self._file_base
        else:
            # Guard disables use of original filename; use safe default
            fname = "upload"
        path = os.path.join(file_dir, fname)
        os.makedirs(file_dir, exist_ok=True)
        tmp_file = open(path, "w+b")
        try:
            tmp_file.write(b"content")
        finally:
            tmp_file.close()
        return path

class FormParser:
    def __init__(self, file_name=None, field_name=None):
        self.file = File(file_name=file_name, field_name=field_name)

    def write(self, data: bytes):
        # Guard is off: do not preserve user filename
        return self.file.save(file_dir="uploads", keep_filename=False, keep_extensions=True)

# Driver
filename = cve_2026_24486_source()
parser = FormParser(file_name=filename)
parser.write(b"file-content")
