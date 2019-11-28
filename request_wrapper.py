import logging
import pycurl
import re
from urllib.parse import urlencode, urljoin, urlsplit
from response import Response
from io import BytesIO

logger = logging.getLogger(__name__)


_resp_headers = {}

def resp_header_parse(header_line):
    # ADD SOURCE SITE
    # HTTP standard specifies that headers are encoded in iso-8859-1.
    # On Python 2, decoding step can be skipped.
    # On Python 3, decoding step is required.
    header_line = header_line.decode('iso-8859-1')

    # Header lines include the first status line (HTTP/1.x ...).
    # We are going to ignore all lines that don't have a colon in them.
    # This will botch headers that are split on multiple lines...
    if ':' not in header_line:
        return

    # Break the header line into header name and value.
    name, value = header_line.split(':', 1)

    # Remove whitespace that may be present.
    # Header lines include the trailing newline, and there may be whitespace
    # around the colon.
    name = name.strip()
    value = value.strip()

    # Header names are case insensitive.
    # Lowercase name here.
    name = name.lower()

    # Now we can actually record the header name and value.
    # Note: this only works when headers are not duplicated, see below.
    _resp_headers[name] = value


def to_key_val_list(value):
    """
    <From requests library>
    Take an object and test to see if it can be represented as a
    dictionary. If it can be, return a list of tuples, e.g.,
    ::
        >>> to_key_val_list([('key', 'val')])
        [('key', 'val')]
        >>> to_key_val_list({'key': 'val'})
        [('key', 'val')]
        >>> to_key_val_list('string')
        Traceback (most recent call last):
        ...
        ValueError: cannot encode objects that are not 2-tuples
    :rtype: list
    """
    if value is None:
        return None

    if isinstance(value, (str, bytes, bool, int)):
        raise ValueError('cannot encode objects that are not 2-tuples')

    if isinstance(value, Mapping):
        value = value.items()

    return list(value)


def encode_params(data):
    """
    <From requests library>
    Encode parameters in a piece of data.
    Will successfully encode parameters when passed as a dict or a list of
    2-tuples. Order is retained if data is a list of 2-tuples but arbitrary
    if parameters are supplied as a dict.
    """
    basestring = (str, bytes)

    if isinstance(data, (str, bytes)):
        return data
    elif hasattr(data, 'read'):
        return data
    elif hasattr(data, '__iter__'):
        result = []
        for k, vs in to_key_val_list(data):
            if isinstance(vs, basestring) or not hasattr(vs, '__iter__'):
                vs = [vs]
            for v in vs:
                if v is not None:
                    result.append(
                        (k.encode('utf-8') if isinstance(k, str) else k,
                            v.encode('utf-8') if isinstance(v, str) else v))
        return urlencode(result, doseq=True)
    else:
        return data

class Session(object):
    def __init__(self, headers=None, cert=None, verify=False, verbose=False):
        self.curl = pycurl.Curl()
        self.curl.setopt(pycurl.CONNECTTIMEOUT, 10)
        if headers is not None:
            assert type(headers) == dict, "headers must be passes in the form of a dict"
            self.headers = headers
        else:
            self.headers = None
        self.cert = cert
        self.verify = verify
        self.verbose = verbose

    
    def request(self, method, url, data, headers, params):
        resp = request


    def get(self, url, headers=None, verbose=None, params=None):
        if headers is None:
            headers = self.headers #TODO
        if verbose is None:
            verbose = self.verbose
        resp = request(url, method="GET", curl=self.curl, cert=self.cert, verify=self.verify, headers=headers, params=params, data=None, verbose=verbose)

        return resp


    def post(self, url, headers=None, data=None, verbose=None, params=None):
        if headers is None:
            headers = self.headers
        if verbose is None:
            verbose = self.verbose
        resp = request(url, method="POST", curl=self.curl, cert=self.cert, verify=self.verify, headers=headers, params=params, data=data, verbose=verbose)

        return resp


def derive_log_stmt(url, method):
    "Log in urllib3 format"
    url_comps = urlsplit(url)
    log_stmt = '%s://%s "%s %s/%s"' % (url_comps[0], url_comps[1], method, url_comps[2], url_comps[3])

    return log_stmt


def request(url, method="GET", curl=None, headers=None, data=None, params=None, verify=True, cert=None, verbose=False):
    if params is not None:
        params_encoded = encode_params(params)
        url = urljoin(url, params_encoded)

    log_stmt = derive_log_stmt(url, method)
    logger.debug(log_stmt)

    if curl is None:
        curl = pycurl.Curl()
        curl.setopt(pycurl.CONNECTTIMEOUT, 10)


    buffer = BytesIO() # Supposedly faster to instantiate new one rather than clearing old buffer
    curl.setopt(curl.URL, url)

    # Verbosity level
    if verbose:
        curl.setopt(pycurl.VERBOSE, 1)

    # For POST
    if method == "POST":
        curl.setopt(pycurl.POST, True)
        curl.setopt(pycurl.POSTFIELDS, data)
    
    # Add headers
    if headers:
        if not type(headers) == dict:
            raise ValueError("headers provided must be in the form of a dict")
        header_list = ["{0}:{1}".format(key,value) for key, value in headers.items()]
        curl.setopt(pycurl.HTTPHEADER, header_list)

    # Verify server against CA store
    if verify:
        curl.setopt(pycurl.SSL_VERIFYPEER, 1)
        curl.setopt(pycurl.SSL_VERIFYHOST, 2)
        if type(verify) == str:
            curl.setopt(pycurl.CAINFO, verify)
    else:
        curl.setopt(pycurl.SSL_VERIFYPEER, 0)
        curl.setopt(pycurl.SSL_VERIFYHOST, 0)

    if cert:
        if not type(cert) == tuple and len(cert) != 2:
            raise ValueError("cert must be a tuple (certificate file, public key file)")
        curl.setopt(curl.SSLCERT, cert[0])
        curl.setopt(curl.SSLKEY, cert[1])
    

    curl.setopt(curl.HEADERFUNCTION, resp_header_parse)
    curl.setopt(curl.WRITEDATA, buffer)
    curl.perform()
    status_code = curl.getinfo(pycurl.HTTP_CODE)
    #curl.close()

    resp_body = buffer.getvalue()

    #print(_resp_headers)

    resp = {
        'body': resp_body,
        'headers': _resp_headers,
        'status_code': status_code
    }
    resp = Response(content = resp_body,
                    status_code = status_code,
                    headers = _resp_headers,
                    request = None
                    )

    return resp





if __name__ == "__main__":
    r = request("https://jsonplaceholder.typicode.com/todos/1", verbose=False)
    #print(r['headers'])
    print(r.status_code)
    print(r.json())
    #print(r.headers)

    r = request("https://jsonplaceholder.typicode.com/todos/1", verbose=True)
    #print(r['headers'])
    print(r.status_code)
    print(r.json())

    r = request("http://localhost:9002", headers={"Content-Type":"application-json", "custonm":"customheader"}, verbose=True)
    #print(r['headers'])
    print(r.status_code)
    print(r.text)

    sample_post_body = {
    "name": "morpheus",
    "job": "leader"
    }
    import json
    json_body = json.dumps(sample_post_body)

    r = request("http://localhost:9002/postjson",method='POST',data=json_body, headers={"Content-Type":"application-json", "custonm":"customheader"}, verbose=True)
    #print(r['headers'])
    print(r.status_code)
    print(r.text)

    ses = Session()
    resp = ses.get("https://jsonplaceholder.typicode.com/todos/1")
    print(r.status_code)


# r = request("https://reqres.in/api/users",method='POST',body=json_body, headers={"Content-Type":"application-json"}, verbose=True)

# #print(r['headers'])
# print(r.status_code)
# print(r.text)




#if cert:
    # self.curl.setopt(pycurl.SSLKEYTYPE, "PEM")
    # self.curl.setopt(pycurl.SSLKEY, WxPayConf_pub.SSLKEY_PATH)
    # self.curl.setopt(pycurl.SSLCERTTYPE, "PEM")
    # self.curl.setopt(pycurl.SSLCERT, WxPayConf_pub.SSLCERT_PATH)


# if curl is None:
#     if 'curl' in globals():
#         curl = globals()['curl']
#     else:
#         curl = pycurl.Curl()
#         curl.setopt(pycurl.CONNECTTIMEOUT, 10)
#         globals()['curl'] = curl