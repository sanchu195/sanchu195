import json
import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification, Trainer, TrainingArguments
from datasets import Dataset
from transformers import DataCollatorWithPadding
from sklearn.metrics import accuracy_score, f1_score
import random

nvd_file_path = "NVD/nvdcve-1.1-recent.json"
with open(nvd_file_path, "r", encoding="utf-8") as file:
    nvd_data = json.load(file)

vulnerabilities = []
cve_items = nvd_data.get("CVE_Items", [])

for item in cve_items:
    cve_id = item["cve"]["CVE_data_meta"]["ID"]
    description = item["cve"]["description"]["description_data"][0]["value"]
    vulnerabilities.append({"cve_id": cve_id, "description": description})

vulnerability_labels = {
    "SQL Injection": 0,
    "Cross-Site Scripting": 1,
    "Command Injection": 2,
    "Directory Traversal": 3,
}

data = {
    "text": [v["description"] for v in vulnerabilities],
    "label": [vulnerability_labels["SQL Injection"] if "SQL" in v["description"] else vulnerability_labels["Cross-Site Scripting"] if "XSS" in v["description"] else vulnerability_labels["Command Injection"] if "command" in v["description"] else vulnerability_labels["Directory Traversal"] for v in vulnerabilities]
}

dataset = Dataset.from_dict(data)

tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")
model = RobertaForSequenceClassification.from_pretrained("microsoft/codebert-base", num_labels=len(vulnerability_labels))

def tokenize_function(examples):
    return tokenizer(examples["text"], truncation=True, padding="max_length", max_length=512)

tokenized_dataset = dataset.map(tokenize_function, batched=True)

split_dataset = tokenized_dataset.train_test_split(test_size=0.2)
train_dataset = split_dataset["train"]
test_dataset = split_dataset["test"]

training_args = TrainingArguments(
    output_dir="./results",
    num_train_epochs=3,
    per_device_train_batch_size=8,
    evaluation_strategy="epoch",
    save_strategy="epoch",
    learning_rate=2e-5,
    load_best_model_at_end=True,
    logging_strategy="epoch",
    report_to=None, 
)

data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

def compute_metrics(p):
    preds = torch.argmax(torch.tensor(p.predictions), axis=1) w
    labels = torch.tensor(p.label_ids)
    accuracy = accuracy_score(labels, preds)
    f1 = f1_score(labels, preds, average='weighted')
    return {"accuracy": accuracy, "f1": f1}

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=test_dataset,
    compute_metrics=compute_metrics,
    data_collator=data_collator,
)

trainer.train()

output_dir = "./saved_multi_class_model"
trainer.save_model(output_dir)