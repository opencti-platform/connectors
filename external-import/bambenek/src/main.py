import traceback

from bambenek_connector import ConnectorBambenek

if __name__ == "__main__":
    try:
        connector = ConnectorBambenek()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
