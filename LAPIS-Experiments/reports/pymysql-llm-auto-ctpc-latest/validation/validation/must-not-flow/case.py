def cve_2024_36039_source():
    # Untrusted input, but used as a VALUE, not a KEY
    return "bob"

class FakeConn:
    def literal(self, v):
        return "'%s'" % str(v).replace("'", "\\'")
    def escape(self, args):
        return args

class FakeCursor:
    def _get_db(self):
        return FakeConn()

    def _escape_args(self, args, conn):
        if isinstance(args, dict):
            # Keys are constant/safe; only values are tainted
            return {key: conn.literal(val) for (key, val) in args.items()}
        if isinstance(args, (tuple, list)):
            return tuple(conn.literal(arg) for arg in args)
        return conn.escape(args)

    def mogrify(self, query, args):
        conn = self._get_db()
        query = query % self._escape_args(args, conn)
        return query

    def _query(self, query):
        return query

    def execute(self, query, args):
        query = self.mogrify(query, args)
        result = self._query(query)
        self._executed = query
        return result

def main():
    user = cve_2024_36039_source()
    # Taint is in the VALUE, not the dict key
    args = {"name": user}
    query = "SELECT * FROM users WHERE name=%(name)s"
    return FakeCursor().execute(query, args)

if __name__ == "__main__":
    print(main())
