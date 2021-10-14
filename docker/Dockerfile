FROM python:3.9-bullseye

# Install requirements
COPY requirements.txt .
RUN python -m pip install -r requirements.txt

# Copy in app code
COPY run.py .
COPY app .

# Create database entries for voters
COPY data/voter_data.json /tmp/voter_data.json
RUN python run.py addvoters -jsonfile /tmp/voter_data.json

# Run on port 0.0.0.0:80
CMD python runserver -a "0.0.0.0" -p 80
