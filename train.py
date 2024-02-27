import tensorflow as tf
from keras.preprocessing import image
import matplotlib.pyplot as plt
from PIL import Image
import tensorflow_hub as hub
import numpy as np
from tensorflow import keras
from tensorflow.keras.models import load_model
from tensorflow.keras import preprocessing
import time
from tensorflow.keras.applications.resnet import ResNet50
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dropout, Dense
from keras.models import Sequential, Model
import splitfolders
import os
from sklearn.utils import class_weight
from keras.callbacks import ModelCheckpoint

# Unzip dataset locally
import zipfile
with zipfile.ZipFile('malimg_dataset.zip', 'r') as zip_ref:
    zip_ref.extractall('malimg_dataset')

# Set ratios to split the data
splitfolders.ratio('malimg_dataset/malimg_paper_dataset_imgs', output="data", seed=1337, ratio=(.8, 0.1, 0.1))

# Set the image size to 150
img_size = 150

# Set the training data
train_datagen = image.ImageDataGenerator(rescale=1./255)
train_generator = train_datagen.flow_from_directory(
        'data/train',
        target_size=(img_size, img_size),
        batch_size=32,
        class_mode='categorical')

# Set the validation data
val_generator = train_datagen.flow_from_directory(
        'data/val',
        target_size=(img_size, img_size),
        batch_size=32,
        class_mode='categorical')

# Set the testing data
test_generator = train_datagen.flow_from_directory(
        'data/test',
        target_size=(img_size, img_size),
        batch_size=32,
        class_mode='categorical')

# Define the model
num_classes = len(train_generator.class_indices)

def malware_model():
    baseModel = ResNet50(weights="imagenet", include_top=False, input_shape=(img_size, img_size, 3))
    for layer in baseModel.layers:
        layer.trainable = False
    headModel = baseModel.output
    headModel = MaxPooling2D(pool_size=(2, 2))(headModel)
    headModel = Flatten(name="flatten")(headModel)
    headModel = Dense(256, activation="relu")(headModel)
    headModel = Dropout(0.5)(headModel)
    headModel = Dense(num_classes, activation="softmax")(headModel)
    model = Model(inputs=baseModel.input, outputs=headModel)
    model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    return model

Malware_model = malware_model()
Malware_model.summary()

# Class weights for handling imbalanced data
y_train = train_generator.classes
class_weights = class_weight.compute_class_weight(class_weight='balanced', classes=np.unique(y_train), y=y_train)
class_weights = dict(enumerate(class_weights))

# Model checkpoint
checkpoint_filepath = 'ResNet_Checkpoints/'
model_checkpoint_callback = ModelCheckpoint(
    filepath=checkpoint_filepath,
    save_weights_only=True,
    monitor='val_accuracy',
    mode='max',
    save_best_only=True)

# Train the model
history = Malware_model.fit(
    train_generator,
    steps_per_epoch=train_generator.samples // train_generator.batch_size,
    validation_data=val_generator,
    validation_steps=val_generator.samples // val_generator.batch_size,
    epochs=10,  # Adjust number of epochs as needed
    class_weight=class_weights,
    callbacks=[model_checkpoint_callback])

# Load best weights
Malware_model.load_weights(checkpoint_filepath)

# Save the model
model_save_path = "ResNet_final.h5"
try:
    Malware_model.save(model_save_path)
    print(f"Model saved successfully to {model_save_path}")
except Exception as e:
    print(f"Error saving model: {e}")

# Evaluate on validation data
scores = Malware_model.evaluate(val_generator)
print('Final ResNet-50 accuracy on validation:', scores[1])

# Evaluate on testing data
scores_test = Malware_model.evaluate(test_generator)
print('Final ResNet-50 accuracy on testing:', scores_test[1])
