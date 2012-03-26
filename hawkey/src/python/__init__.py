import _hawkey

Repo = _hawkey.Repo

SYSTEM_REPO_NAME = _hawkey.SYSTEM_REPO_NAME
CMDLINE_REPO_NAME = _hawkey.CMDLINE_REPO_NAME

QUERY_KEYNAME_MAP = {
    'name'    : _hawkey.PKG_NAME,
    'summary' : _hawkey.PKG_SUMMARY,
    'repo'    : _hawkey.PKG_REPO,
    'latest'  : _hawkey.PKG_LATEST,
    'updates' : _hawkey.PKG_UPDATES,
    'obsoleting' : _hawkey.PKG_OBSOLETING
}

ICASE = _hawkey.ICASE
QUERY_FT_MAP = {
    'eq' : _hawkey.EQ,
    'gt' : _hawkey.GT,
    'lt' : _hawkey.LT,
    'neq' : _hawkey.NEQ,
    'gte' : _hawkey.EQ | _hawkey.GT,
    'lte' : _hawkey.EQ | _hawkey.LT,
    'substr'  : _hawkey.SUBSTR,
    'glob' : _hawkey.GLOB,
}

Sack = _hawkey.Sack
Goal = _hawkey.Goal

class Package(_hawkey.Package):
    def evr_eq(self, pkg):
        return self.evr_cmp(pkg) == 0

    def evr_gt(self, pkg):
        return self.evr_cmp(pkg) > 0

    def evr_lt(self, pkg):
        return self.evr_cmp(pkg) < 0

class Query(object):
    def __init__(self, sack):
        self._query = _hawkey.Query(sack)
        self.sack = sack
        self.result = None

    def __iter__(self):
        if not self.result:
            self.result = self._query.run()
        for p in self.result:
            yield p

    def _parse_filter_args(self, lst, dct):
        args = []
        filter_flags = 0
        for flag in lst:
            if not flag in [ICASE]:
                raise ValueError("unrecognized flag: %s" % flag)
            filter_flags |= flag
        for (k, match) in dct.items():
            split = k.split("__", 1)
            if len(split) == 1:
                args.append((QUERY_KEYNAME_MAP[split[0]],
                             QUERY_FT_MAP["eq"]|filter_flags,
                             match))
            elif len(split) == 2:
                (keyname, filter_type) = split
                if not keyname in QUERY_KEYNAME_MAP:
                    raise ValueError("Unrecognized key name: %s" % keyname)
                if not filter_type in QUERY_FT_MAP:
                    raise ValueError("Unrecognized filter type: %s" % filter_type)
                args.append((QUERY_KEYNAME_MAP[keyname],
                             QUERY_FT_MAP[filter_type]|filter_flags,
                             match))
            else:
                raise ValueError("keyword arguments given to filter() need be "
                                 "in <key>__<comparison type>=<value> format")
        return args

    def count(self):
        if not self.result:
            self.result = self._query.run()
        return len(self.result)

    def filter(self, *lst, **kwargs):
        map(lambda arg_tuple: self._query.filter(*arg_tuple),
            self._parse_filter_args(lst, kwargs))
        return self

    def provides(self, name, **kwargs):
        raise NotImplementedError("hawkey.Query.provides is not implemented yet")