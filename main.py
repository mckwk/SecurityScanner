from log_and_file_managers.common_logger import logger
from ttkthemes import ThemedTk
from UI.gui import GUI

if __name__ == "__main__":
    logger.info("Starting GUI application")

    root = ThemedTk(theme="arc")
    app = GUI(root)
    root.mainloop()
