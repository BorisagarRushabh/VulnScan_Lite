# Use official Python runtime
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Copy all files from backend folder
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port
EXPOSE 8000

# Start Flask app using Gunicorn
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8000"]
