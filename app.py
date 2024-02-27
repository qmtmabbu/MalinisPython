import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib  # To save and load the trained model

# Load the dataset (assuming the CSV file is in the same directory as your Python script)
malware_data = pd.read_csv('./malware_dataset.csv')  # Replace 'your_file_path' with the path to your dataset

# Features (X) and labels (y)
X = malware_data.drop('hash', axis=1)  # Features (excluding the 'hash' column)
y = malware_data['hash']  # Labels ('hash' column)

# Split the dataset into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize the Random Forest classifier
classifier = RandomForestClassifier(n_estimators=100, random_state=42)

# Train the classifier
classifier.fit(X_train, y_train)

# Make predictions on the test set
predictions = classifier.predict(X_test)

# Calculate accuracy and display results
accuracy = accuracy_score(y_test, predictions)
print(f'Accuracy: {accuracy:.2f}')

# Display classification report
print(classification_report(y_test, predictions))

# Save the trained model to a file
joblib.dump(classifier, 'malware_detection_model.joblib')