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

    def save(self, file_dir, keep_filename, keep_extensions):
        if file_dir is not None and keep_filename:
            fname = self._file_base + self._ext if keep_extensions else self._file_base
            path = os.path.join(file_dir, fname)
            tmp_file = open(path, "w+b")
            try:
                tmp_file.write(b"x")
            finally:
                tmp_file.close()
            return path
        else:
            path = os.path.join(file_dir or ".", "safe.tmp")
            tmp_file = open(path, "w+b")
            tmp_file.write(b"x")
            tmp_file.close()
            return path


class FormParser:
    def __init__(self, file_name=None):
        self.file = File(file_name=file_name)

    def write(self, data):
        # keep_filename=True triggers the risky keep-filename path join
        return self.file.save(".", keep_filename=True, keep_extensions=True)


def main():
    filename = cve_2026_24486_source()
    parser = FormParser(file_name=filename)
    return parser.write(b"file-content")


if __name__ == "__main__":
    main()
