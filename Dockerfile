# Stage 1: Nginx to serve static files
FROM nginx:alpine as nginx_stage

# Copy the static HTML content to the Nginx default directory
COPY ui/index.html /usr/share/nginx/html/index.html

# Stage 2: Flask App for API
FROM python:3.9-alpine as flask_stage

# Set the working directory inside the container
WORKDIR /domain_analysis

# Install necessary system dependencies for Flask, and libraries (including whois and nslookup)
RUN apk update && apk add --no-cache \
    whois \
    bind-tools \
    libpq-dev \
    && rm -rf /var/cache/apk/*

# Copy the requirements file and install Python dependencies
COPY domain_analysis/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend application code to the container
COPY domain_analysis/ /domain_analysis/

# Expose the Flask API port for internal access (not exposed externally)
EXPOSE 8888

# Stage 3: Final container with both Nginx and Flask
FROM nginx:alpine as final_stage

# Install Python and pip in the final container (only what's necessary for Flask)
RUN apk add --no-cache python3 py3-pip

# Copy the Nginx content and configuration from the previous stages
COPY --from=nginx_stage /usr/share/nginx/html /usr/share/nginx/html
COPY ui/nginx.conf /etc/nginx/nginx.conf

# Copy the necessary Python application files
COPY --from=flask_stage /domain_analysis /domain_analysis
COPY --from=flask_stage /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages

# Set the environment variables for Flask
ENV PYTHONPATH=/usr/local/lib/python3.9/site-packages:$PYTHONPATH
ENV FLASK_APP=/domain_analysis/app.py
ENV FLASK_RUN_HOST=127.0.0.1
ENV FLASK_RUN_PORT=8888

# Expose the Nginx port for the frontend (port 80)
EXPOSE 80

# Default command to run both Flask and Nginx
CMD ["sh", "-c", "python3 /domain_analysis/app.py & nginx -g 'daemon off;'"]
