__author__ = 'MAHMADI'

class apk:



    def __init__(self, sha, md5 = ''):
        self.sha = sha
        self.md5 = md5
        self.size = 0
        self.callgraph_edges = 0
        self.time_susiss = 0

    def set_sha(self, sha):
        self.sha = sha

    def set_time_1ss(self, time):
        self.time_1ss = time

    def set_time_1ss(self, time):
        self.time_10ss = time

    def set_time_1ss(self, time):
        self.time_30ss = time

    def set_size(self, size):
        self.size = size

    def set_callgraph_edges(self, edges):
        self.callgraph_edges = edges

    def printall(self, data = 'all'):
        if data == 'all':
            print self.sha, self.md5, self.size, self.callgraph_edges, self.time_susiss
            return True
        elif data == 'NNone':
            if self.callgraph_edges != 0 and int(self.time_susiss) != 0:
                print self.sha, self.md5, self.size, self.callgraph_edges, self.time_susiss
                return True
            else:
                return False

    def printinfo(self):
        print self.size, self.callgraph_edges, self.time_susiss