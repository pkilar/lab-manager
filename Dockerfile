# Use Alpine Linux with Python 3.14
FROM python:3.14-alpine

# Set working directory
WORKDIR /app

# Install system dependencies
# - ipmitool: Required for IPMI server management
# - gcc, musl-dev, linux-headers: Build dependencies for Python packages
RUN apk add --no-cache \
    ipmitool \
    gcc \
    musl-dev \
    linux-headers

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY templates/ templates/

# Create directory for SQLite database
RUN mkdir -p /app/instance

# Expose Flask port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "app.py"]
