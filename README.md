# URL Threat Detector

This project is a web-based application for detecting malicious URLs. It uses a hybrid ensemble machine learning model to classify URLs into different categories (benign, phishing, malware, defacement).

## Features

-   Web interface with a mock login and a URL input form.
-   Provides a prediction for the URL type.
-   Explains *why* a URL is classified as malicious.

## Model

This application uses a "double-check" system with two distinct machine learning models:

1.  **Main (TF-IDF) Model:** A `LogisticRegression` classifier that analyzes the text of the URL using a TF-IDF vectorizer. This model is trained by `url_threat_detector.py`.

2.  **Lexical Model:** A `RandomForestClassifier` that is trained on *lexical features* of the URL (e.g., its length, number of dots, presence of suspicious keywords). This model is trained by `lexical_model_trainer.py`.

When a URL is submitted, it is evaluated by both models. If either model flags the URL as malicious, the system will report it as a threat.

## How to Retrain the Model

1.  **Download a dataset.** A large, balanced dataset of URLs is required. The file should be in CSV format and contain 'url' and 'label' columns. A suitable dataset can be found [here](https://drive.google.com/file/d/1ta5CUG8yYTJrjTFeQkq-GCZmWbC3m8CE/view?usp=sharing). Download this file and save it as `phishing_dataset_1.csv` in the root of the project.

2.  **Run the training scripts.** From the project's root directory, run the following commands in order:
    ```bash
    # Train the main model
    python3 url_threat_detector.py --dataset phishing_dataset_1.csv

    # Train the lexical model
    python3 lexical_model_trainer.py --dataset phishing_dataset_1.csv
    ```
    This will train both models on the same dataset and save their respective files to the `saved_model` and `lexical_model` directories.

## How to Run the Web Application

1.  **Install dependencies.**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the Flask application.**
    ```bash
    python3 app.py
    ```
    The application will be available at `http://1227.0.0.1:5000`.
