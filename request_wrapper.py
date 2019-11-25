import pycurl
import re
from response import Response
from io import BytesIO



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



def request(url, method="GET", headers=None, body=None, verify=True, cert=None, verbose=False):
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
        curl.setopt(pycurl.POSTFIELDS, body)
    
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
    curl.close()

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


    r = request("http://localhost:9002/postjson",method='POST',body=json_body, headers={"Content-Type":"application-json", "custonm":"customheader"}, verbose=True)
    #print(r['headers'])
    print(r.status_code)
    print(r.text)



# r = request("https://reqres.in/api/users",method='POST',body=json_body, headers={"Content-Type":"application-json"}, verbose=True)

# #print(r['headers'])
# print(r.status_code)
# print(r.text)




#if cert:
    # self.curl.setopt(pycurl.SSLKEYTYPE, "PEM")
    # self.curl.setopt(pycurl.SSLKEY, WxPayConf_pub.SSLKEY_PATH)
    # self.curl.setopt(pycurl.SSLCERTTYPE, "PEM")
    # self.curl.setopt(pycurl.SSLCERT, WxPayConf_pub.SSLCERT_PATH)
