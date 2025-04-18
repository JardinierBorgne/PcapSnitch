import os
import csv

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def save_csv(data, filename, headers=None):
    ensure_dir(os.path.dirname(filename))
    with open(filename, mode='w', newline='') as f:
        writer = csv.writer(f)
        if headers:
            writer.writerow(headers)
        for row in data:
            writer.writerow(row)
