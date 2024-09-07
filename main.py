# File: main.py

from ttkthemes import ThemedTk
from UI.gui import GUI

if __name__ == "__main__":
    root = ThemedTk(theme="arc")
    app = GUI(root)
    root.mainloop()