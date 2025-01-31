from lib.radar import RadarConnector

if __name__ == "__main__":
    try:
        connector = RadarConnector()
        connector.run()
    except Exception as e:
        print(f"Error running connector: {str(e)}")
        exit(1)
