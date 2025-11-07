# Use official lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy backend files into container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port (just for reference)
EXPOSE 8000

# Start Flask using Gunicorn
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:$PORT"]
