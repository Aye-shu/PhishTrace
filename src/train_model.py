"""
Train baseline phishing detection model using Random Forest and Logistic Regression.
Part of PhishTrace project.
"""

import pandas as pd
import arff
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, confusion_matrix, classification_report
)

# Create models directory
os.makedirs('models', exist_ok=True)

def load_data(filepath):
    """Load and prepare the ARFF dataset."""
    print("Loading dataset...")
    with open(filepath, 'r') as f:
        dataset = arff.load(f)
    
    df = pd.DataFrame(dataset['data'], columns=[attr[0] for attr in dataset['attributes']])
    
    # Convert all columns to numeric floats
    df = df.astype(float)
    
    # Separate features and target
    X = df.drop('Result', axis=1)
    y = df['Result']
    
    # Map labels: -1 (phishing) to 1, and 1 (safe) to 0
    # This is standard practice for binary classification metrics
    y = y.map({-1: 1, 1: 0})
    
    return X, y

def train_and_evaluate(model, X_train, X_test, y_train, y_test, model_name):
    """Train a model and print evaluation metrics."""
    print(f"\n{'='*50}")
    print(f"Training: {model_name}")
    print(f"{'='*50}")
    
    # Train
    model.fit(X_train, y_train)
    
    # Predict
    y_pred = model.predict(X_test)
    
    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    return model, {
        'model_name': model_name,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1
    }

def main():
    # Load data
    X, y = load_data('data/raw/Training Dataset.arff')
    
    print(f"Features: {X.shape[1]}")
    print(f"Samples: {X.shape[0]}")
    
    # Split data (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining set: {X_train.shape[0]}")
    print(f"Test set: {X_test.shape[0]}")
    
    # Train models
    results = []
    
    # Model 1: Logistic Regression
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr_model, lr_results = train_and_evaluate(
        lr, X_train, X_test, y_train, y_test, "Logistic Regression"
    )
    results.append(lr_results)
    
    # Model 2: Random Forest
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model, rf_results = train_and_evaluate(
        rf, X_train, X_test, y_train, y_test, "Random Forest"
    )
    results.append(rf_results)
    
    # Save best model
    best_model = rf_model if rf_results['f1'] > lr_results['f1'] else lr_model
    best_name = "Random Forest" if rf_results['f1'] > lr_results['f1'] else "Logistic Regression"
    
    joblib.dump(best_model, 'models/phishing_model.pkl')
    joblib.dump(X.columns.tolist(), 'models/feature_names.pkl')
    
    print(f"\n{'='*50}")
    print(f"Best model: {best_name}")
    print(f"Saved to: models/phishing_model.pkl")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()