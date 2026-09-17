import threading
import sys
from kafka.producer import run as producer_run
from features.watcher import main as watcher_main

prod_thread = threading.Thread(target=producer_run, daemon=True)
prod_thread.start()

watcher_main()
