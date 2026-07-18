import os


def cve_2026_24486_source():
    return "../../evil.txt"


class File:
    def __init__(self, file_name, field_name=None, config=None):
        if file_name is not None:
            base, ext = os.path.splitext(file_name)
            self._file_base = base
            self._ext = ext
        else:
            self._file_base = "upload"
            self._ext = ".bin"

    def save(self, file_dir):
        # Guard/sanitizer: do NOT preserve the original filename; never join with fname
        path = os.path.join(file_dir or ".", "safe.tmp")
        tmp_file = open(path, "w+b")
        try:
            tmp_file.write(b"x")
        finally:
            tmp_file.close()
        return path


class FormParser:
    def __init__(self, file_name=None):
        self.file = File(file_name=file_name)

    def write(self, data):
        # keep_filename effectively disabled by using a safe path builder
        return self.file.save(".")


def main():
    filename = cve_2026_24486_source()
    parser = FormParser(file_name=filename)  # user filename provided
    return parser.write(b"file-content")


if __name__ == "__main__":
    main()
