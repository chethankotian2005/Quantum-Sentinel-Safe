import json
import logging

def process_data(input_file, output_file):
    logging.info("Starting data processing")
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Do some transformations
    processed = [d for d in data if d.get('active', False)]
    
    with open(output_file, 'w') as f:
        json.dump(processed, f)
        
    logging.info("Processing complete")
