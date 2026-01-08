# Use official lightweight Python image
FROM python:3.10-slim

# Create a working directory inside the container
WORKDIR /app

# 1. Copy requirements.txt first
# This allows Docker to cache the installed dependencies step.
# If you change your code but not requirements.txt, this step is skipped.
COPY requirements.txt .

# 2. Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 3. Copy the rest of the server code
# Since the build context is the 'server' folder, this copies 
# everything in that folder (app.py, etc.) into /app
COPY . .

# Expose port 5000
EXPOSE 5000

# Run the application
CMD ["python3", "app.py"]
