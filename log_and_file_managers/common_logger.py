import config
from log_and_file_managers.logger_manager import LoggerManager

logger_manager = LoggerManager(config.LOG_FILE)
logger = logger_manager.get_logger()
