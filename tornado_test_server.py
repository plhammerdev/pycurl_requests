import tornado.ioloop
import tornado.web
import json
import uuid

__UPLOADS__ = "/Users/nxm/Projects/python/pycurl_requests"

PORT = 9002

class Upload(tornado.web.RequestHandler):
    def post(self):
        fileinfo = self.request.files.items()
        print(fileinfo)
        # print("fileinfo is", fileinfo)
        # fname = fileinfo['filename']
        # extn = os.path.splitext(fname)[1]
        # cname = str(uuid.uuid4()) + extn
        # fh = open(__UPLOADS__ + cname, 'w')
        # fh.write(fileinfo['body'])
        #self.finish(cname + " is uploaded!! Check %s folder" %__UPLOADS__)
        self.finish()


class PostJSON(tornado.web.RequestHandler):
    def post(self):
        data = json.loads(self.request.body.decode('utf-8'))
        print('Got JSON data:', data)
        self.write({ 'got' : 'your data' })
        self.finish()

        
class MainHandler(tornado.web.RequestHandler):
    def get(self):
        print(self.request.headers)
        self.write("Hello, world")

if __name__ == "__main__":
    application = tornado.web.Application([
            (r"/", MainHandler),
            (r"/upload", Upload),
            (r"/postjson", PostJSON),
        ], debug=True)
    print("Starting loop on port: %d" % PORT)
    application.listen(PORT)
    tornado.ioloop.IOLoop.current().start()


