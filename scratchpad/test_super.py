#!/usr/bin/env python
class foo:
    def __init__(self):
        self.refresh()
    def refresh(self):
        self.properties = {}
        self.properties["foo"] = 1

class bar(foo):
    def __init__(self):
        super().__init__()
        self.refresh()
    def refresh(self):
        super().refresh()
        self.properties["bar"] = 2

    @property
    def foo(self):
        return self.properties["foo"]
    @property
    def bar(self):
        return self.properties["bar"]

instance = bar()
print(instance.foo)
print(instance.bar)
