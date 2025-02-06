import traceback

from connector import ProofpointEtIntelligenceConnector

if __name__ == "__main__":
    # Entry point of the script
    try:
        connector = ProofpointEtIntelligenceConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
