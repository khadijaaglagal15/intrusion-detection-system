# Intrusion Detection System

A Machine Learning-based Intrusion Detection System designed to detect and classify network attacks using the CICIDS2017 dataset.

## Project Overview

This project uses Machine Learning techniques to analyze network traffic and identify potential intrusions. A Random Forest model is trained to distinguish between benign traffic and different types of attacks.

The system provides a web-based interface built with Flask, allowing users to upload network traffic data in CSV format and obtain prediction results.

## Technologies

* Python
* Flask
* Pandas
* Scikit-learn
* Random Forest
* HTML
* CSS
* JavaScript
* SQLite

## Dataset

The project uses the **CICIDS2017** dataset.

Due to GitHub's file size limitations, the original large dataset files are not included in this repository.

## Main Features

* Upload network traffic data in CSV format
* Detect potential network intrusions
* Classify different attack types
* Display prediction results through a web interface
* User authentication using SQLite

## Project Structure

```text
Intrusion-Detection/
├── app.py
├── model/
├── templates/
├── static/
├── docs/
│   └── Rapport_IDS.pdf
├── dataset/
├── requirements.txt
└── README.md
```

## Installation

Clone the repository:

```bash
git clone https://github.com/khadijaaglagal15/intrusion-detection-system.git
cd intrusion-detection-system
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```bash
.venv\Scripts\activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

## Run the Application

Start the Flask application:

```bash
python app.py
```

Then open the local address displayed in the terminal in your web browser.

## Project Report

The complete project report is available in the `docs/` folder.

## Author

**Khadija Aglagal**

Engineering Student in Data Science, Big Data and Artificial Intelligence
ENSIASD Taroudant
