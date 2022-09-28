FROM python:3.9-bullseye

# Install prerequisite requirements
RUN apt-get update
RUN apt-get -y install python3-pip

# Install requirements
COPY requirements.txt .
RUN python -m pip install -r requirements.txt

COPY chn.env .

# Copy in app code
RUN mkdir /app
WORKDIR /app
COPY run.py .
COPY app ./app
COPY chnregister.py .
RUN python chnregister.py -p run.py -d <key> -n SAVIRegistrar -u https://0.0.0.0 -k -o /etc/registrar/registrar.json

# Create database entries for voters
COPY data/voter_data.json /tmp/voter_data.json
RUN mkdir /app/data
RUN python run.py addvoters -jsonfile /tmp/voter_data.json

# Run on port 0.0.0.0:80
CMD hypercorn --bind 0.0.0.0:80 app:app
