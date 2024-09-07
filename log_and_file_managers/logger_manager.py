import logging
import os
import io

class CustomFilter(logging.Filter):
    def filter(self, record):
        # Exclude specific log messages
        return "Starting new HTTPS connection" not in record.getMessage()

class LoggerManager:
    def __init__(self, log_file):
        self.log_file = log_file
        self.log_stream = io.StringIO()
        self._setup_logging()

    def _setup_logging(self):
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                pass  # Create the file if it doesn't exist

        # Create a custom logger
        self.logger = logging.getLogger('NotificationManager')
        self.logger.setLevel(logging.DEBUG)

        # Create handlers
        stream_handler = logging.StreamHandler(self.log_stream)
        stream_handler.setLevel(logging.DEBUG)
        stream_handler.addFilter(CustomFilter())

        # Create formatters and add it to handlers
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        stream_handler.setFormatter(formatter)

        # Add handlers to the logger
        self.logger.addHandler(stream_handler)
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