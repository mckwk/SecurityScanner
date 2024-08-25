from ttkthemes import ThemedTk
from gui import GUI

if __name__ == "__main__":
    root = ThemedTk(theme="arc")
    app = GUI(root)
    root.mainloop()