from log_and_file_managers.logger_manager import LoggerManager
import config

logger_manager = LoggerManager(config.LOG_FILE)
logger = logger_manager.get_logger()