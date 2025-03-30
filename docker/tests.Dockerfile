FROM avatartwo/avatar2:latest

# Install test dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3-pytest \
        python3-pyudev \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir --break-system-packages serial

# Copy the code and check wether the copied is correct
COPY . /avatartwo/avatar2 
RUN ls -la /avatartwo/avatar2/ && \
    if [ ! -f /avatartwo/avatar2/pyproject.toml ]; then echo "pyproject.toml not found!"; exit 1; fi && \
    if [ ! -d /avatartwo/avatar2/tests ]; then echo "tests directory not found!"; exit 1; fi && \
    echo "Project structure verified"

# Set working directory
WORKDIR /avatartwo/avatar2

# Command to run tests
CMD ["python3", "-m", "pytest", "tests/", "-v"]