def source():
    return "name)s OR 1=1 -- "


def sink(query):
    return query


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def test():
    key = source()
    if key not in {"name", "email"}:
        return
    args = {key: "safe-value"}
    query = "SELECT * FROM users WHERE name=%(name)s"
    escaped = {key: quote(val) for (key, val) in args.items()}
    query = query % escaped
    sink(query)
