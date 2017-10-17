from __future__ import absolute_import, print_function

import codecs
from six import text_type
from symbolic import SourceView
from sentry.utils.strings import codec_lookup

__all__ = ['SourceCache', 'SourceMapCache']


def is_utf8(codec):
    try:
        name = codecs.lookup(codec).name
    except Exception:
        return False
    return name in ('utf-8', 'ascii')


class SourceCache(object):
    def __init__(self):
        self._cache = {}
        self._errors = {}
        self._aliases = {}

    def __contains__(self, url):
        url = self._get_canonical_url(url)
        return url in self._cache

    def _get_canonical_url(self, url):
        if url in self._aliases:
            url = self._aliases[url]
        return url

    def get(self, url):
        return self._cache.get(self._get_canonical_url(url))

    def get_errors(self, url):
        url = self._get_canonical_url(url)
        return self._errors.get(url, [])

    def alias(self, u1, u2):
        if u1 == u2:
            return

        if u1 in self._cache or u1 not in self._aliases:
            self._aliases[u1] = u1
        else:
            self._aliases[u2] = u1

    def add(self, url, source, encoding=None):
        url = self._get_canonical_url(url)

        if not isinstance(source, SourceView):
            if isinstance(source, text_type):
                source = source.encode('utf-8')
            # If an encoding is provided and it's not utf-8 compatible
            # we try to re-encoding the source and create a source view
            # from it.
            elif encoding is not None and not is_utf8(encoding):
                try:
                    source = source.decode(encoding).encode('utf-8')
                except UnicodeError:
                    pass
            source = SourceView.from_bytes(source)
        self._cache[url] = source

    def add_error(self, url, error):
        url = self._get_canonical_url(url)
        self._errors.setdefault(url, [])
        self._errors[url].append(error)


class SourceMapCache(object):
    def __init__(self):
        self._cache = {}
        self._mapping = {}

    def __contains__(self, sourcemap_url):
        return sourcemap_url in self._cache

    def link(self, url, sourcemap_url):
        self._mapping[url] = sourcemap_url

    def add(self, sourcemap_url, sourcemap_view):
        self._cache[sourcemap_url] = sourcemap_view

    def get(self, sourcemap_url):
        return self._cache.get(sourcemap_url)

    def get_link(self, url):
        sourcemap_url = self._mapping.get(url)
        if sourcemap_url:
            sourcemap = self.get(sourcemap_url)
            return (sourcemap_url, sourcemap)
        return (None, None)
