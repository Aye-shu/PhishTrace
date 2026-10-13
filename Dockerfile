# Use the official Playwright image from Microsoft (includes browsers & dependencies)
FROM mcr.microsoft.com/playwright:v1.52.0-noble

# Set the working directory
WORKDIR /app

# Copy all your project files into the container
COPY . .

# Install the Python Playwright package
RUN pip install playwright

# The command that runs when the container starts
CMD ["python3", "src/evidence/evidence_collector.py"]