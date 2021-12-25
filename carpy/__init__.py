from modulepy import ProcessModule
from multiprocessing import Queue
from timerpp import Timer
from loguru import logger as log
from kivymd.uix.relativelayout import MDRelativeLayout


class CarPyWidget(MDRelativeLayout):
    daemon = True
    timer: Timer = None

    def __init__(self, queue: Queue, refresh_rate: int = 100):
        MDRelativeLayout.__init__(self)
        self.timer = Timer(self.callback)
        self.widget_queue = queue
        self.refresh_rate = refresh_rate
        self.build()

    def callback(self):
        while not self.widget_queue.empty():
            data = self.widget_queue.get()
            try:
                self.update_data(data)
            except Exception as e:
                log.exception(e)

    def update_data(self, data: dict):
        pass

    def build(self):
        pass

    def stop(self):
        self.timer.stop()
        self.timer.join()

    def start(self):
        self.timer.start(self.refresh_rate)


class CarPyModule(ProcessModule):
    data: dict = {}
    has_widget: bool = False
    is_system: bool = False
    widget: CarPyWidget = None
    widget_cls = CarPyWidget
    widget_queue: Queue = None

    def __init__(self):
        ProcessModule.__init__(self)
        self.widget_queue = Queue()
        if self.has_widget:
            self.widget = self.widget_cls(self.widget_queue)
            self.widget.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.has_widget:
            self.widget.stop()
            self.widget.join()

    def enqueue(self, data: dict):
        ProcessModule.enqueue(self, data)
        if self.has_widget:
            self.widget_queue.put(data)


__all__ = ['CarPyModule', 'log', 'CarPyWidget']
