def cve_2024_36039_source():
    # Simulate untrusted input controlling the mapping key
    return "name"

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
            # Dict comprehension preserves keys
            return {key: conn.literal(val) for (key, val) in args.items()}
        if isinstance(args, (tuple, list)):
            return tuple(conn.literal(arg) for arg in args)
        return conn.escape(args)

    def mogrify(self, query, args):
        conn = self._get_db()
        # Percent-format substitution with mapping
        query = query % self._escape_args(args, conn)
        return query

    def _query(self, query):
        # Sink
        return query

    def execute(self, query, args):
        query = self.mogrify(query, args)
        result = self._query(query)
        self._executed = query
        return result

def main():
    key = cve_2024_36039_source()
    # Tainted variable used as dict key
    args = {key: "safe-value"}
    query = "SELECT * FROM users WHERE name=%(name)s"
    return FakeCursor().execute(query, args)

if __name__ == "__main__":
    print(main())
