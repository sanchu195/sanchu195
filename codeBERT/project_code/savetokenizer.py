from transformers import RobertaTokenizer

tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")

output_dir = "./saved_multi_class_model"
tokenizer.save_pretrained(output_dir)