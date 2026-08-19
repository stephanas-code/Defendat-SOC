import onnx
from onnx.external_data_helper import convert_model_to_external_data

# Load the model
model = onnx.load("lstm_autoencoder.onnx")

# Convert weights to external data
convert_model_to_external_data(
    model,
    all_tensors_to_one_file=True,
    location="lstm_autoencoder.onnx.data",
    size_threshold=0,      # Export every tensor
    convert_attribute=False
)

# Save the model
onnx.save(model, "lstm_autoencoder.onnx")