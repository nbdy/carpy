from kivymd.app import MDApp
from kivy.lang import Builder
from kivymd.theming import ThemableBehavior
from kivymd.uix.list import OneLineListItem, MDList

from modulepy.manager import ModuleManager
from carpy import log
from carpy.ModuleManagerUI import ModuleManagerUI

kv = '''
Screen:
    MDNavigationLayout:
        x: toolbar.height
    
        ScreenManager:
            Screen:
                BoxLayout:
                    orientation: 'vertical'
                
                    MDToolbar:
                        id: toolbar
                        title: "CarPy"
                        pos_hint: {"top": 1}
                        elevation: 10
                        left_action_items:
                            [['menu', lambda x: nav_drawer.set_state("open")]]
                
                    RelativeLayout:
                        id: module_container
        
        MDNavigationDrawer:
            id: nav_drawer
            ScrollView:
                DrawerList:
                    id: module_list
'''


class DrawerList(ThemableBehavior, MDList):
    def set_color_item(self, instance_item):
        for item in self.children:
            if item.text_color == self.theme_cls.primary_color:
                item.text_color = self.theme_cls.text_color
                break
        instance_item.text_color = self.theme_cls.primary_color


class CarPyApp(MDApp):
    cfg: dict = None
    module_manager: ModuleManager = None
    module_manager_ui: ModuleManagerUI = None

    def on_module_selected(self, btn):
        self.root.ids.nav_drawer.set_state("close")
        log.debug("on_module_selected: {}", btn.text)

        module = None
        widget = None
        module_manager_selected = btn.text == "ModuleManager"
        if not module_manager_selected:
            module = self.module_manager.get_module(btn.text)
            if module is not None and module.has_widget:
                widget = module.widget
        else:
            widget = self.module_manager_ui
            self.module_manager_ui.update_modules(self.module_manager.modules)

        log.debug("on_module_selected: {}", widget)

        if module is not None:
            module.on_selected()

        if widget is not None:
            log.info("Showing widget: {}", widget)
            self.root.ids.module_container.clear_widgets()
            self.root.ids.module_container.add_widget(widget)

    def __init__(self, cfg: dict):
        MDApp.__init__(self, title='CarPy')
        self.cfg = cfg
        self.module_manager = ModuleManager()
        self.module_manager.module_directory_path = self.cfg['module_directory']
        self.module_manager.reload_hooks.append(self.update_module_drawer)
        self.module_manager_ui = ModuleManagerUI()
        self.module_manager.reload_hooks.append(self.module_manager_ui.update_modules)

    def update_module_drawer(self, modules: dict):
        self.root.ids.module_list.clear_widgets()
        self.root.ids.module_list.add_widget(
            OneLineListItem(text="ModuleManager", on_release=self.on_module_selected)
        )
        for module in modules.values():
            if module.has_widget:
                self.root.ids.module_list.add_widget(
                    OneLineListItem(text=module.information.name, on_release=self.on_module_selected)
                )

    def on_start(self):
        self.fps_monitor_start()
        self.module_manager.reload()
        self.module_manager.start()

    def on_stop(self):
        self.module_manager.reload_hooks.clear()
        self.module_manager.stop()

    def build(self):
        return Builder.load_string(kv)
