import logging
LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(filename)s:%(funcName)s] %(message)s"
logging.basicConfig(
     level=logging.INFO,
    format= LOG_FORMAT,
    handlers=[
        logging.FileHandler("log.txt", mode='a'),
        logging.StreamHandler()  # İstersen konsola da yazsın
    ]
)

logger = logging.getLogger("secure-comm")