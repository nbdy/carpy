### module development

```python
from carpy.modules import Base, ModuleCategory
# extend modules.Base

class MyModule(Base):
    # set required information for the manager
    # category is used for loading the modules in order
    category = ModuleCategory.SYSTEM
    # load is used so that we can load/unload modules at runtime
    load = True
    
    # Base is a subclass of runnable.Runnable
    # the functions work, start, stop are available
    def work(self):
        # now do your work here
        print("spam")
```