from kivymd.uix.relativelayout import MDRelativeLayout
from kivymd.uix.datatables import MDDataTable
from kivy.metrics import dp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.button import MDFlatButton

from carpy import log


class ModuleManagerUI(MDRelativeLayout):
    index_cache: list = []

    btn_switch_state = None
    btn_reload_modules = None

    def on_row_selected(self, instance_table, current_row):
        if bool(current_row[0]):
            self.btn_switch_state.text = "Disable"
        else:
            self.btn_switch_state.text = "Enable"
        print(instance_table, current_row)

    def on_btn_switch_state_pressed(self):
        log.debug("on_btn_switch_state_pressed")

    def on_btn_reload_modules_pressed(self):
        log.debug("on_btn_reload_modules_pressed")

    def _make_button_toolbar(self):
        self.btn_switch_state = MDFlatButton(text="Enable", on_release=self.on_btn_switch_state_pressed)
        self.btn_switch_state.disabled = True

        self.btn_reload_modules = MDFlatButton(text="Reload", on_release=self.on_btn_reload_modules_pressed)

        r = MDBoxLayout(orientation='horizontal')
        r.add_widget(self.btn_switch_state)
        r.add_widget(self.btn_reload_modules)
        return r

    def __init__(self, **kwargs):
        MDRelativeLayout.__init__(self, **kwargs)
        self.table = MDDataTable(
            use_pagination=True,
            check=True,
            column_data=[
                ("Running", dp(32), "center", "1fr"),
                ("Name", dp(32), "center", "1fr"),
                ("Version", dp(16), "center", "1fr"),
                ("Dependencies", dp(32), "center", "1fr"),
                ("GUI", dp(16), "center", "1fr"),
                ("System", dp(16), "center", "1fr"),
            ]
        )
        self.table.bind(on_check_press=self.on_row_selected)

        self.add_widget(self._make_button_toolbar())
        self.add_widget(self.table)

    @staticmethod
    def get_icon(name: str):
        return name, [255, 255, 255, 1], ""

    def add_module(self, module):
        log.debug(module)
        self.table.row_data.append((
            module.do_run, module.information.name, str(module.information.version), len(module.dependencies),
            self.get_icon(("check" if module.has_widget else "close")),
            self.get_icon(("check" if module.is_system else "close"))
        ))

    def update_module(self, module):
        log.debug(module)
        self.table.row_data[self.index_cache.index(module.information.name)] = (
            module.do_run, module.information.name, str(module.information.version), len(module.dependencies),
            self.get_icon(("check" if module.has_widget else "close")),
            self.get_icon(("check" if module.is_system else "close"))
        )

    def update_modules(self, modules: dict):
        for k, v in modules.items():
            if k not in self.index_cache:
                self.index_cache.append(k)
                self.add_module(v)
            else:
                self.update_module(v)
