#!/usr/bin/python

import sys
import os

class GUINode(object):
    def __init__(self):
        self.icon="../default.gif"
        self.size=0
        self.color="red"
        self.is_closed=False
    def show1(self):
        s="icon=%s, size=%d, color=%s" % (self.icon, int(self.size), self.color)
        if hasattr(self,"layout"):
            s+=", layout=%s" % (getattr(self,"layout"))
        s+="\n"
        return s
    def show2(self):
        s=""
        for k in self.__dict__.keys(): # traverse all attributes --- introspection
            v=self.__dict__[k]
            s+="%s=%s\t" % (k,v)
        s+="\n"
        return s
    def __str__(self):
        if self.is_closed:
            return "this GUI node has been closed."
        #return self.show1()
        return self.show2()

    '''
    to indicate that this GUI node (e.g., a window) has been closed; thus further access (e.g., print it) 
    will get nothing but a warning; this might be useful for sanity purposes
    '''
    def close(self): 
        # del self.icon, self.color, self.size # more efficient way of doing this
        for k in self.__dict__.keys(): # traverse all attributes --- introspection
            if k!="is_closed":
                delattr(self,k)
        self.is_closed=True

class TextLabel(GUINode):
    def __init__(self):
        super(TextLabel,self).__init__()
        self.color="black"
        self.size=12
        self.font="serif" # new attribute
    def __str__(self):
        if self.is_closed:
            return "this text label has been closed."
        if hasattr(self,'icon'):
            del self.icon  # delete the property inapplicable to text labels, yet wanting to reuse show2()
        return self.show2()

def loadConfig(obj,fname):
    fh=file(fname)
    for ln in fh.readlines():
        ln=ln.lstrip().rstrip()
        if len(ln)<1:
            continue
        kv = ln.split('=',2)
        # scheme 1: only load defined attributes
        #if hasattr(obj, kv[0]):
        #    setattr(obj, kv[0], kv[1])
        # scheme 2: construct the object fully dynamically
        setattr(obj, kv[0], kv[1])

if __name__ == "__main__":
    if len(sys.argv)>=1:
        import string # dynamic scoping
        node = GUINode()
        loadConfig(node, "./config.txt")
        print node

        label = TextLabel()
        loadConfig(label, "./config.txt")
        print label

        label.close()
        print label

        sys.exit(0)
    sys.exit(-1)
    
