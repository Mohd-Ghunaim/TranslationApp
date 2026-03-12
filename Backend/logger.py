import logging
import os

if not os.path.exists("logs"):
  os.mkdir("logs")

login_logger = logging.getLogger("login_logger")
login_handler = logging.FileHandler("logs/login.log")
login_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
login_logger.addHandler(login_handler)
login_logger.setLevel(logging.INFO)

translation_logger = logging.getLogger("translation_logger")
translation_handler = logging.FileHandler("logs/translation.log")
translation_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
translation_logger.addHandler(translation_handler)
translation_logger.setLevel(logging.INFO)

error_logger = logging.getLogger("error_logger")
error_handler = logging.FileHandler("logs/errors.log")
error_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
error_logger.addHandler(error_handler)
error_logger.setLevel(logging.ERROR)