# Use the official Python Playwright image from Microsoft
FROM mcr.microsoft.com/playwright/python:v1.52.0-noble

# Set the working directory
WORKDIR /app

# Copy all your project files into the container
COPY . .

# Install Python dependencies (including Playwright)
RUN pip install -r requirements.txt

# The command that runs when the container starts
CMD ["python3", "src/evidence/evidence_collector.py"]