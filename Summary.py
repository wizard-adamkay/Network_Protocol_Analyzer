import tkinter as tk


class NewWindow(tk.Toplevel):
    def __init__(self, master=None):
        super().__init__(master=master)
        self.title("Summary")
        self.geometry("1000x600")