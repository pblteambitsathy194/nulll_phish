"""
Model Training Script
Trains a Random Forest Classifier with 100 estimators for phishing detection.
Saves the resulting model to phishing_model.pkl.
"""

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

def train_phishing_model():
    print("🚀 Starting Random Forest model training...")

    # For demonstration/scaffold purposes, we generate synthetic data matching the 22 features.
    # In a real scenario, you would load your 'phishing_dataset.csv' here.
    # Features are typically -1 (phishing), 0 (suspicious), or 1 (legitimate).
    
    num_samples = 1000
    num_features = 22
    
    # Generate random features (-1, 0, 1)
    X = np.random.choice([-1, 0, 1], size=(num_samples, num_features))
    
    # Generate labels (1 for legitimate, 0 for phishing)
    # Simple rule: if sum of features is positive, it's more likely legitimate
    y = (np.sum(X, axis=1) > 0).astype(int)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Initialize Random Forest with 100 estimators as requested
    print("🌲 Initializing Random Forest with 100 estimators...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    
    # Train
    clf.fit(X_train, y_train)
    
    # Evaluate
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"📊 Model Accuracy: {accuracy * 100:.2f}%")
    print("\n📝 Classification Report:")
    print(classification_report(y_test, y_pred))

    # Save the model
    model_filename = "phishing_model.pkl"
    joblib.dump(clf, model_filename)
    print(f"\n✅ Model saved successfully to {model_filename}")

if __name__ == "__main__":
    train_phishing_model()
