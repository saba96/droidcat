__author__ = 'MAHMADI'
from apk import apk

class apks:

    def __init__(self):
        self.apks = {}

    def add(self, apk):
        self.apks[apk.sha] = apk

    def printall(self):
        for key, value in self.apks.iteritems():
            print key
            value.printinfo()

    def get_values(self):
        return self.apks.values()