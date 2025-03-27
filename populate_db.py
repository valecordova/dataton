import csv
import requests

# Configuración
BASE_URL = "http://localhost:8000"
TOKEN_URL = f"{BASE_URL}/token"
USERNAME = "string"
PASSWORD = "string"

def load_conversations(file_path):
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            conversation_data = {
                "conversation_id": row["conversation_id"],
                "conversation_history": row["conversation_history"],
                "translation": row["translation"]
            }
            response = requests.post(f"{BASE_URL}/conversations/", json=conversation_data)
            print(response.json())
            
def load_responses(file_path):
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            response_data = {
                "response": row["response"],
                "translation": row["translation"],
                "conversation_id": row.get("conversation_id"),
                "tutor_identity": row.get("tutor_identity")
            }
            response = requests.post(f"{BASE_URL}/responses/", json=response_data)
            print(response.json())
            
def load_entropies(file_path):
    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            entropy_data = {
                "conversation_id": row["conversation_id"],
                "tutor_identity": row.get("tutor_identity"),
                "entropy": float(row["entropy"]),
                "assigned": row.get("assigned", "False").lower() == "true",
                "annotated": row.get("annotated", "False").lower() == "true"
            }
            response = requests.post(f"{BASE_URL}/entropies/", json=entropy_data)
            print(response.json())
            
if __name__ == "__main__":
    load_conversations("data/conversation_history_translation.csv")
    load_responses("data/responses_translated.csv")
    load_entropies("data/final_output.csv")