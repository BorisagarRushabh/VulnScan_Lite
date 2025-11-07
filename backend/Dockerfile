# Use official Python image
FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

# TEMPORARY: run Flask directly to confirm it starts
CMD ["python", "app.py"]
