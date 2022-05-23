FROM python:3.9-bullseye

# Install prerequisite requirements
RUN apt-get update
RUN apt-get -y install python3-pip

# Install requirements
COPY requirements.txt .
RUN python -m pip install -r requirements.txt

# Copy in app code
RUN mkdir /app
WORKDIR /app
COPY run.py .
COPY app ./app

# Create database entries for voters
COPY data/voter_data.json /tmp/voter_data.json
RUN mkdir /app/data
RUN python run.py addvoters -jsonfile /tmp/voter_data.json

# Run on port 0.0.0.0:80
CMD python run.py runserver -a "0.0.0.0" -p 80
