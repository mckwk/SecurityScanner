import io
import logging
import os
import sys

class CustomFilter(logging.Filter):
    def filter(self, record):
        return "Starting new HTTPS connection" not in record.getMessage()

class LoggerManager: # singleton
    _instance = None

    def __new__(cls, log_file):
        if cls._instance is None:
            cls._instance = super(LoggerManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, log_file):
        if self._initialized:
            return
        self.log_file = log_file
        self.log_stream = io.StringIO()
        self._setup_logging()
        self._initialized = True

    def _setup_logging(self):
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        if not os.path.exists(self.log_file):
            open(self.log_file, 'w').close()

        self.logger = logging.getLogger('Logger')
        self.logger.setLevel(logging.DEBUG)

        # Check if the logger already has handlers to avoid adding duplicates
        if not self.logger.handlers:
            # Stream handler for log stream
            stream_handler = logging.StreamHandler(self.log_stream)
            stream_handler.setLevel(logging.DEBUG)
            stream_handler.addFilter(CustomFilter())

            # File handler for log file
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

            # Stream handler for terminal output
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.DEBUG)
            console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

            self.logger.addHandler(stream_handler)
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)
            self.logger.info("\n" + "_" * 50 + "\n")
            self.logger.debug("Logging setup complete.")

    def get_logger(self):
        return self.logger

    def prepend_log_file(self):
        new_logs = self.log_stream.getvalue()
        with open(self.log_file, 'r') as f:
            existing_logs = f.read()
        with open(self.log_file, 'w') as f:
            f.write(new_logs + existing_logs)
        self.log_stream.seek(0)
        self.log_stream.truncate(0)