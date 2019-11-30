import chardet
import json

class Response(object):
    """
    Source/credit: https://github.com/psf/requests/blob/master/requests/models.py
    """

    __attr__ = [
        'content', 'status_code', 'headers', 'url', 'history',
        'encoding', 'reason', 'cookies', 'elapsed', 'request'
    ]

    def __init__(self, content, status_code, headers, request, url):

        self.content = content
        self.status_code = status_code
        self.headers = headers
        self.encoding = None
        self.request = request
        self.url = url

    
    def __repr__(self):
        return '<Response [%s]>' % (self.status_code)

    def raise_for_status(self):
        http_error_msg = ''

        if 400 <= self.status_code < 600:
            reason = self.text

            if self.status_code < 500:
                http_error_msg = u'%s Client Error: %s for url: %s' % (self.status_code, reason, self.url)
            else:
                http_error_msg = u'%s Server Error: %s for url: %s' % (self.status_code, reason, self.url)

        if http_error_msg:
            raise ValueError(http_error_msg)
        

    @property
    def apparent_encoding(self):
        """The apparent encoding, provided by the chardet library."""
        return chardet.detect(self.content)['encoding']


    @property
    def text(self):
        """Content of the response, in unicode.
        If Response.encoding is None, encoding will be guessed using
        ``chardet``.
        The encoding of the response content is determined based solely on HTTP
        headers, following RFC 2616 to the letter. If you can take advantage of
        non-HTTP knowledge to make a better guess at the encoding, you should
        set ``r.encoding`` appropriately before accessing this property.
        """

        # Try charset from content-type
        content = None
        encoding = self.encoding

        if not self.content:
            return str('')

        # Fallback to auto-detected encoding.
        if self.encoding is None:
            encoding = self.apparent_encoding
        # Forcefully remove BOM from UTF-8
        elif self.encoding.lower() == 'utf-8':
            encoding = 'utf-8-sig'

        # Decode unicode from given encoding.
        try:
            content = str(self.content, encoding, errors='replace')
        except (LookupError, TypeError):
            # A LookupError is raised if the encoding was not found which could
            # indicate a misspelling or similar mistake.
            #
            # A TypeError can be raised if encoding is None
            #
            # So we try blindly encoding.
            content = str(self.content, errors='replace')

        return content

    def json(self, **kwargs):
        r"""Returns the json-encoded content of a response, if any.
        :param \*\*kwargs: Optional arguments that ``json.loads`` takes.
        :raises ValueError: If the response body does not contain valid json.
        """

        if not self.encoding and self.content and len(self.content) > 3:
            # No encoding set. JSON RFC 4627 section 3 states we should expect
            # UTF-8, -16 or -32. Detect which one to use; If the detection or
            # decoding fails, fall back to `self.text` (using chardet to make
            # a best guess).
            encoding = "utf-8"#guess_json_utf(self.content) #TODO
            if encoding is not None:
                try:
                    return json.loads(
                        self.content.decode(encoding), **kwargs
                    )
                except UnicodeDecodeError:
                    # Wrong UTF codec detected; usually because it's not UTF-8
                    # but some other 8-bit codec.  This is an RFC violation,
                    # and the server didn't bother to tell us what codec *was*
                    # used.
                    pass
        return json.loads(self.text, **kwargs)