import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification

model_path = "./saved_multi_class_model" 
loaded_model = RobertaForSequenceClassification.from_pretrained(model_path) 
loaded_tokenizer = RobertaTokenizer.from_pretrained(model_path) 

label_mapping = {
    0: "SQL Injection",
    1: "Cross-Site Scripting (XSS)",
    2: "Command Injection",
    3: "Directory Traversal",
}

def classify_text(text):
    inputs = loaded_tokenizer(text, return_tensors="pt", truncation=True, padding="max_length", max_length=512)
    outputs = loaded_model(**inputs)
    predictions = torch.argmax(outputs.logits, axis=1)  # Get the predicted class
    return label_mapping[predictions.item()]  # Return the corresponding vulnerability type

ctf_sql_injection = """
# Potential SQL injection
def get_user_by_id(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return execute_query(query)  # Vulnerable to SQL injection
"""

ctf_xss = """
# Potential cross-site scripting
def render_user_profile(username):
    return f"<div>{username}</div>"  # Vulnerable to XSS
"""

ctf_command_injection = """
import os

# Potential command injection
def delete_user_files(username):
    os.system(f"rm -rf /home/{username}")  # Vulnerable to command injection
"""

ctf_directory_traversal = """
# Potential directory traversal
def read_user_file(username, filename):
    filepath = f"/home/{username}/files/{filename}"
    with open(filepath, 'r') as f:
        return f.read()  # Vulnerable to directory traversal
"""

sql_result = classify_text(ctf_sql_injection) 
xss_result = classify_text(ctf_xss) 
command_injection_result = classify_text(ctf_command_injection)
directory_traversal_result = classify_text(ctf_directory_traversal) 

print("Classification Result for SQL Injection:", sql_result)
print("Classification Result for XSS:", xss_result)
print("Classification Result for Command Injection:", command_injection_result)
print("Classification Result for Directory Traversal:", directory_traversal_result)
